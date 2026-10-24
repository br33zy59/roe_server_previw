"""Лобби и прокси игрового тракта: один процесс вместо лобби на C# и прокси.

Процесс принимает подключение клиента на 127.0.0.1:8001, сам отвечает на
базовые пакеты лобби (IT/SA/DT, порт C#-эмулятора не нужен), разбирает
login-id клиента (`-uid=`) и выдаёт ему личность из реестра пользователей,
после чего ведёт игровую часть лобби: команду, подбор, JOIN_INSTANCE и часы.
"""
import argparse
import asyncio
import datetime as dt
import json
import signal
from pathlib import Path
import sys
import struct
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'server/directory'))
from listener import Capture
from roe_protocol_2022 import FrameBuffer, client_heartbeat, heartbeat_reply, server_stamp, dt_plain
from roe_team_2022 import client_message, server_message, team_body
from roe_custom_room_2022 import (
    decode_create, decode_room_list, decode_quit, decode_remove, decode_change_pos,
    encode_create_response, encode_room_list_response, encode_echo_response,
    encode_result_response, encode_enter_ntf, encode_enter_ntf_empty,
    quit_variants, quit_ntf_variants,
)

# Кастомная комната: код запроса -> (код ответа, разбор тела).
CUSTOM_ROOM_MESSAGES = {
    0x736f: (0x7370, decode_room_list),
    0x7371: (0x7372, decode_create),
    0x7373: (0x7374, decode_remove),
    0x7377: (0x7378, decode_quit),
    0x7381: (0x7382, decode_change_pos),
}

# Комнаты этого процесса лобби: видны всем соединениям (вкладка Custom).
CUSTOM_STATE = {'rooms': {}, 'next_id': 1}


def custom_room_messages(code, body, parsed, team):
    """Ответы на запрос комнаты: первый - RSP, дальше серверные уведомления."""
    if code == 0x7371:
        room_id = CUSTOM_STATE['next_id']
        CUSTOM_STATE['next_id'] += 1
        CUSTOM_STATE['rooms'][room_id] = {
            'id': room_id, 'owner': parsed['uid'], 'name': parsed['name'],
            'password': parsed['password'], 'mode': parsed['mode'],
            'perspective': parsed['perspective'], 'map_id': parsed['map_id'],
            'max_players': parsed['max_players'], 'players': 1, 'state': 1}
        team['room_id'] = room_id
        team['custom_variant'] = 0
        room = CUSTOM_STATE['rooms'][room_id]
        nickname = team.get('nickname') or ''
        # Подтверждённая цепочка: CREATE_RSP (только u32 result), затем полный
        # ENTER_NTF с записью комнаты и локальным актёром. Локальный актёр
        # НЕ входит через OTHER_ENTER_NTF (0x737C).
        return [(0x7372, encode_create_response(0)),
                (0x737b, encode_enter_ntf(room, parsed['uid'], nickname))]
    if code == 0x736f:
        # Подтверждённая раскладка: page/page_count/room_count + записи комнат.
        # Ответ дополнительно задерживается на 100 мс при отправке: панель
        # XVersion RspRoomList отбрасывает ответы до готовности окна.
        return [(0x7370, encode_room_list_response(CUSTOM_STATE['rooms'].values(),
                                                   page=parsed['page']))]
    if code == 0x7373:
        # Подтверждённая цепочка владельца: REMOVE_RSP (u32 0), затем пустой
        # снимок 0x737B (room_id=0) — ветка очистки окна комнаты. Комната
        # удаляется из списка.
        room_id = team.get('room_id') or parsed.get('room_id')
        if room_id in CUSTOM_STATE['rooms']:
            del CUSTOM_STATE['rooms'][room_id]
        team['room_id'] = None
        return [(0x7374, encode_result_response(0)),
                (0x737b, encode_enter_ntf_empty())]
    if code == 0x7377:
        # RSP подтверждает результат (u32 0), а закрытие окна клиент делает
        # после серверного уведомления 0x737D - шлём все кандидаты.
        attempt = team.get('quit_attempts', 0)
        variants = quit_variants(parsed['room_id'], team.get('room_id'))
        index = min(attempt, len(variants) - 1)
        team['quit_attempts'] = attempt + 1
        team['custom_variant'] = index
        room_id = team.get('room_id') or parsed['room_id']
        room = CUSTOM_STATE['rooms'].get(room_id)
        if room:
            # Комнату пока не удаляем: уходят и безуспешные повторы запроса.
            room['players'] = max(0, room.get('players', 1) - 1)
        outputs = [(0x7378, variants[index])]
        outputs += [(0x737d, payload) for payload in
                    quit_ntf_variants(room_id, team.get('uid') or 0)]
        return outputs
    if code == 0x7381:
        team['custom_variant'] = 0
        team['position'] = parsed['position']
        return [(0x7382, encode_echo_response(body))]
    raise ValueError('Неизвестный запрос кастомной комнаты')
from roe_join_instance_2022 import (
    JoinInstanceNotification, JoinInstanceResponse,
    encode_join_instance_notification, encode_join_instance_response,
    decode_join_instance_request,
)
import ipaddress
from local_cosmetics_2022 import LocalCosmetics
from roe_clock_2022 import LobbyClockStream
from lobby_actor_uid_2022 import LobbyActorUIDStream
from lobby_login_2022 import LobbyLogin


def load_user_registry(path):
    """Реестр uid -> профиль (users/registry.json менеджера пользователей)."""
    if path is None:
        return {}
    file = Path(path)
    if not file.is_file():
        return {}
    data = json.loads(file.read_text(encoding='utf-8'))
    if not isinstance(data, dict):
        raise ValueError('реестр пользователей должен быть объектом')
    registry = {}
    for key, row in data.items():
        if not isinstance(row, dict) or row.get('actor_uid') is None:
            continue
        registry[str(int(key))] = {
            'name': row.get('name', ''),
            'nickname': row.get('nickname', '') or row.get('name', ''),
            'actor_uid': int(str(row['actor_uid']), 0),
        }
    return registry


class LocalLobbyUpstream:
    """Лобби внутри процесса: тот же интерфейс, что у TCP-соединения."""

    def __init__(self, lobby):
        self.lobby = lobby
        self.queue = asyncio.Queue()
        self.closed = False

    def write(self, data):
        # write() у StreamWriter синхронный, очередь без ограничения размера.
        answer = self.lobby.feed(data)
        if answer and not self.closed:
            self.queue.put_nowait(answer)

    async def read(self, limit=65536):
        if self.closed:
            return b''
        return await self.queue.get()

    async def drain(self):
        return None

    def can_write_eof(self):
        return True

    def write_eof(self):
        return None

    def close(self):
        if not self.closed:
            self.closed = True
            self.queue.put_nowait(b'')

    async def wait_closed(self):
        return None


def load_join_experiment(path):
    """Явные синтетические поля; маршрут разрешён только на loopback IPv4."""
    if path is None:
        return None
    value = json.loads(Path(path).read_text(encoding='utf-8'))
    notification = JoinInstanceNotification(**value['notification'])
    response = dict(value['response'])
    prefix, address, port = response['route'].split(':')
    if not ipaddress.IPv4Address(address).is_loopback or not 1 <= int(port) <= 65535:
        raise ValueError('JOIN_INSTANCE: требуется loopback endpoint')
    response['route'] = response['route'].encode('ascii')
    for name in ('block_88', 'block_98'):
        response[name] = bytes.fromhex(response[name])
    response = JoinInstanceResponse(**response)
    delay = value['delay_after_found']
    if type(delay) not in (float, int) or not 0 <= delay <= 60:
        raise ValueError('JOIN_INSTANCE: задержка должна быть от 0 до 60 секунд')
    return notification.instance_id, encode_join_instance_notification(notification), encode_join_instance_response(response), delay


async def serve(args, ready=None, stop=None):
    team_enabled = getattr(args, 'team_reply', False)
    nickname = getattr(args, 'team_nickname', 'Player')
    novice = getattr(args, 'novice_state', None)
    training_enabled = getattr(args, 'training_reply', False)
    if novice is not None and (not team_enabled or novice not in (0, 1, 2)):
        raise ValueError('novice-state требует team-reply и значение 0/1/2')
    match_enabled = getattr(args, 'match_reply', False)
    if training_enabled and (not match_enabled or novice != 1):
        raise ValueError('training-reply требует match-reply и novice-state=1')
    estimate = getattr(args, 'match_estimate', 5)
    found_delay = getattr(args, 'match_found_delay', None)
    auto_match_seconds = getattr(args, 'auto_match_seconds', None)
    if auto_match_seconds is not None and (not training_enabled or auto_match_seconds < 0):
        raise ValueError('auto-match-seconds: needs training-reply and a delay >= 0')
    if found_delay is not None and (not match_enabled or found_delay < 0):
        raise ValueError('match-found-delay требует match-reply и неотрицательную задержку')
    if match_enabled and not team_enabled:
        raise ValueError('Для match-reply нужен team-reply')
    cosmetic_path = getattr(args, 'local_cosmetics_config', None)
    cosmetics = LocalCosmetics(cosmetic_path) if cosmetic_path else None
    join_path = getattr(args, 'join_instance_config', None)
    join_provider = getattr(args, 'join_provider', None)
    join_cache = {'value': None, 'mtime': None}

    def current_join(map_id=None):
        # Актуальные данные комнаты. Провайдер (в том же процессе) отдаёт
        # комнату под карту, которую запросил клиент; иначе берётся файл.
        if join_provider is not None:
            return join_provider(map_id)
        if not join_path:
            return None
        try:
            mtime = Path(join_path).stat().st_mtime
        except OSError:
            return None
        if join_cache['mtime'] != mtime:
            join_cache['value'] = load_join_experiment(join_path)
            join_cache['mtime'] = mtime
        return join_cache['value']

    if current_join() is not None and (not training_enabled or found_delay is None):
        raise ValueError('JOIN_INSTANCE требует training-reply и match-found-delay')
    if not 0 <= estimate <= 0xffffffff:
        raise ValueError('Оценка ожидания должна быть U32')
    key = args.session_key_file.read_bytes()
    if len(key) != 16:
        raise ValueError('Файл session key должен содержать ровно 16 бинарных байт')
    registry = load_user_registry(getattr(args, 'users_registry', None))
    local_lobby_enabled = bool(getattr(args, 'local_lobby', False))
    if local_lobby_enabled and not Path(getattr(args, 'lobby_ck', ROOT/'private/lobby-ck.bin')).is_file():
        raise ValueError('Для локального лобби нужен private/lobby-ck.bin')
    run = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S')+'-heartbeat-'+uuid.uuid4().hex[:8]
    capture_dir = getattr(args, 'capture_dir', None)
    capture = Capture(Path(capture_dir) if capture_dir else args.output/run)
    if stop is None:
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        # В фоне оболочка может игнорировать SIGINT; задаём явное завершение захвата.
        if sys.platform != 'win32':
            for signum in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(signum, stop.set)
    tasks = set()
    players = {}
    totals = {'connections': 0, 'heartbeat_requests': 0, 'heartbeat_replies': 0, 'inspection_errors': 0, 'team_replies': 0, 'match_replies': 0, 'custom_room_replies': 0, 'match_found_notifications': 0, 'novice_notifications': 0, 'join_notifications': 0, 'join_requests': 0, 'join_responses': 0, 'login_identities': 0}

    def status():
        value = {'state': 'running', 'reply_enabled': args.reply, 'team_reply_enabled': team_enabled, 'match_reply_enabled': match_enabled, 'novice_state': novice, 'training_reply_enabled': training_enabled,
                 'players': list(players.values()), **totals}
        path = capture.directory/'status.json'
        temporary = path.with_suffix('.tmp')
        temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')
        temporary.replace(path)

    async def handle(reader, writer):
        task = asyncio.current_task()
        tasks.add(task)
        connection = uuid.uuid4().hex[:12]
        info = {'connection': connection}
        clock_stream = LobbyClockStream(key) if getattr(args,'local_server_clock',False) else None
        actor_stream = LobbyActorUIDStream(key,args.actor_uid,
                                           profile_nickname=getattr(args,'profile_nickname','') or None) if getattr(args,'actor_uid',None) is not None else None
        local_lobby = None
        local_upstream = None
        identity_resolved = False
        players[connection] = {'connection': connection, 'uid': None, 'actor_uid': None,
                               'nickname': None, 'since': time.time()}
        if local_lobby_enabled:
            # Своё лобби на соединение: базовые ответы и login-id клиента.
            local_lobby = LobbyLogin(args.lobby_ck, key)
            local_upstream = LocalLobbyUpstream(local_lobby)
        totals['connections'] += 1
        capture.record('connect', **info, remote=writer.get_extra_info('peername'))
        status()
        upstream = None
        pumps = []
        outgoing = asyncio.Lock()
        clock = {'stamp': None, 'at': None}
        frames = {'client_to_server': FrameBuffer(), 'server_to_client': FrameBuffer()}
        enabled = {'client_to_server': True, 'server_to_client': True}
        last_counter = None
        team = {'uid': None, 'body': None, 'searching': False, 'generation': 0, 'novice_sent': False, 'training': False, 'cosmetics_sent': False, 'requested': None, 'room_id': None}
        join_state = {'sent': False, 'replied': False}
        async def notify_found(generation, force=False):
            await asyncio.sleep(found_delay)
            if (not team['searching'] and not force) or team['generation'] != generation or writer.is_closing():
                return
            if not enabled['server_to_client'] or clock['stamp'] is None:
                return
            stamp = (clock['stamp'] + int((time.monotonic()-clock['at'])*25)) & 0xffffffff
            response = server_message(0x6e2d, struct.pack('>I', 0), stamp, key)
            async with outgoing:
                writer.write(response)
                capture.record('data', response, direction='server_to_client', origin='match_probe', **info)
                await writer.drain()
            team['searching'] = False
            totals['match_found_notifications'] += 1
            capture.record('match_found', code='0x6e2d', forced=bool(force), **info)
            status()
            join = current_join(team['requested'][4] if team['requested'] else None)
            # Локальный preview: после Match Found всегда отдаём адрес единственной
            # комнаты (Solo/Squad, TPP/FPP, Training/Battle — только UI клиента).
            if join is not None and not join_state['sent']:
                await asyncio.sleep(join[3])
                if team['generation'] != generation or writer.is_closing() or not enabled['server_to_client']:
                    return
                stamp = (clock['stamp'] + int((time.monotonic()-clock['at'])*25)) & 0xffffffff
                response = server_message(0xd77, join[1], stamp, key)
                async with outgoing:
                    writer.write(response)
                    # Состояние выставляется до drain: запрос может прийти немедленно.
                    join_state['sent'] = True
                    capture.record('data', response, direction='server_to_client', origin='join_probe', **info)
                    await writer.drain()
                totals['join_notifications'] += 1
                capture.record('join_notification', instance_id=join[0], synthetic=True, **info)
                status()

        try:
            if local_upstream is not None:
                up_reader = upstream = local_upstream
            else:
                up_reader, upstream = await asyncio.wait_for(asyncio.open_connection('127.0.0.1', args.upstream_port), 5)

            async def pump(source, destination, direction):
                nonlocal last_counter, actor_stream, identity_resolved
                while data := await source.read(65536):
                    # По умолчанию передаём исходные байты. Явный режим меняет
                    # только UNIX timestamp1f5f до первой установки native epoch.
                    if direction == 'server_to_client':
                        if clock_stream is not None:
                            data,updates=clock_stream.feed(data)
                            for update in updates:
                                capture.record('local_server_clock',synthetic=True,**update,**info)
                            if not data:
                                continue
                        if local_lobby is not None and not identity_resolved and local_lobby.uid is not None:
                            # Логин клиента разобран: личность берётся из реестра,
                            # иначе остаётся личность профиля комнаты.
                            identity_resolved = True
                            account = registry.get(str(local_lobby.uid))
                            if account is None:
                                capture.record('login_unknown', uid=local_lobby.uid,
                                               fallback_actor_uid=hex(args.actor_uid) if getattr(args, 'actor_uid', None) else None,
                                               **info)
                            else:
                                actor_stream = LobbyActorUIDStream(key, account['actor_uid'],
                                                                   profile_nickname=account['nickname'] or None)
                                players[connection].update(uid=local_lobby.uid,
                                                          actor_uid=hex(account['actor_uid']),
                                                          nickname=account['nickname'])
                                capture.record('login_identity', uid=local_lobby.uid,
                                               actor_uid=hex(account['actor_uid']),
                                               nickname=account['nickname'], **info)
                                totals['login_identities'] += 1
                        if actor_stream is not None:
                            data, updates = actor_stream.feed(data)
                            for update in updates:
                                kind = update.pop('kind', 'local_actor_uid')
                                capture.record(kind,synthetic=True,**update,**info)
                            if not data:
                                continue
                        async with outgoing:
                            destination.write(data)
                            capture.record('data', data, direction=direction, origin='upstream', **info)
                            await destination.drain()
                    else:
                        destination.write(data)
                        capture.record('data', data, direction=direction, origin='client', **info)
                        await destination.drain()
                    if not enabled[direction]:
                        continue
                    try:
                        for frame in frames[direction].feed(data):
                            if direction == 'server_to_client':
                                stamp = server_stamp(frame, key)
                                if stamp is not None:
                                    clock.update(stamp=stamp, at=time.monotonic())
                                if team_enabled:
                                    plain = dt_plain(frame, key)
                                    if cosmetics and plain and len(plain) >= 10:
                                        # Порядок штатной инициализации нужен для поиска
                                        # позднего сброса wardrobe. Только opcode/длина,
                                        # без AUTH, UID и содержимого чужого сообщения.
                                        upstream_code = struct.unpack_from('>H', plain, 4)[0]
                                        if upstream_code != 0x1f75:
                                            capture.record('cosmetic_upstream_order', code=hex(upstream_code),
                                                           body_length=len(plain)-10, **info)
                                    if plain and len(plain) == 39 and struct.unpack_from('>H', plain, 4)[0] == 0x32b:
                                        # ENTER_GAME_RSP payload+12 задаёт UID последующих заголовков.
                                        if struct.unpack_from('>I', plain, 30)[0] == 0:
                                            team['uid'] = struct.unpack_from('>Q', plain, 22)[0]
                                            if cosmetics and team['uid'] and not team['cosmetics_sent']:
                                                async with outgoing:
                                                    for code, body in cosmetics.initial(team['uid']):
                                                        response = server_message(code, body, stamp, key)
                                                        writer.write(response)
                                                        capture.record('data', response, direction='server_to_client', origin='local_cosmetics', **info)
                                                    await writer.drain()
                                                team['cosmetics_sent'] = True
                                                capture.record('cosmetics_issued', gun_skins=len(cosmetics.ids), characters=len(cosmetics.characters), accessories=len(cosmetics.accessories), clothes=len(cosmetics.clothes), **info)
                                            if novice is not None and team['uid'] and not team['novice_sent']:
                                                response = server_message(0x6e35, struct.pack('>I', novice), stamp, key)
                                                async with outgoing:
                                                    writer.write(response)
                                                    capture.record('data', response, direction='server_to_client', origin='training_probe', **info)
                                                    await writer.drain()
                                                team['novice_sent'] = True
                                                totals['novice_notifications'] += 1
                                                capture.record('novice_notification', value=novice, code='0x6e35', **info)
                                                status()
                                                if auto_match_seconds is not None and not team['searching']:
                                                    # The client waits in the event center until the
                                                    # player presses Play. The room starts the
                                                    # training match itself after the delay.
                                                    async def auto_start_match(generation=team['generation']):
                                                        await asyncio.sleep(auto_match_seconds)
                                                        if team['searching'] or team['generation'] != generation:
                                                            return
                                                        await notify_found(generation, force=True)
                                                    pumps.append(asyncio.create_task(auto_start_match()))
                                                    capture.record('auto_match_armed', delay_seconds=auto_match_seconds, **info)
                                continue
                            if cosmetics and team['cosmetics_sent'] and enabled['server_to_client']:
                                message = client_message(frame, key)
                                if message and message[1] == team['uid']:
                                    # Метаданные действий гардероба: неизвестные тела,
                                    # AUTH и идентификаторы аккаунта не журналируем.
                                    if message[0] not in (0x1f75,0x1f5e,0x71ae,0x1b59):
                                        capture.record('cosmetic_client_order',code=hex(message[0]),length=len(message[2]),**info)
                                    if message[0] in range(0x73a1,0x73ba) or message[0] in (0x48a,0x54df,0x54e2) or message[0] == 0x3e80 and len(message[2]) == 10:
                                        capture.record('cosmetic_request', code=hex(message[0]), length=len(message[2]), fields_hex=message[2].hex() if len(message[2]) <= 128 else None, **info)
                                    replies, action = cosmetics.handle(message[0], message[2],message[1])
                                    if action:
                                        stamp = (clock['stamp'] + int((time.monotonic()-clock['at'])*25)) & 0xffffffff
                                        async with outgoing:
                                            for code, body in replies:
                                                response = server_message(code, body, stamp, key)
                                                writer.write(response)
                                                capture.record('data', response, direction='server_to_client', origin='local_cosmetics', **info)
                                            await writer.drain()
                                        capture.record('cosmetic_action', action=action, request=hex(message[0]), selected=dict(cosmetics.selected), **info)
                            if team_enabled:
                                message = client_message(frame, key)
                                if message and message[0] in (0x701d, 0x702f):
                                    code, uid, body = message
                                    reason = None
                                    # В части клиентских сообщений (PULL_INFO, часы)
                                    # поле по смещению 22 содержит метку времени, а не
                                    # uid. Настоящий uid берём из ENTER_GAME_RSP.
                                    claimed = uid if uid >= 2**32 else None
                                    if not team['uid']:
                                        reason = 'Нет ENTER_GAME_RSP'
                                    elif claimed is not None and claimed != team['uid']:
                                        reason = 'UID не совпал с ENTER_GAME_RSP'
                                    elif not enabled['server_to_client'] or clock['stamp'] is None:
                                        reason = 'Нет проверенного серверного потока'
                                    elif code == 0x702f and team['body'] is None:
                                        # PULL_INFO до CREATE: команда ещё не создана.
                                        # Отвечать нельзя - клиент считает, что он в
                                        # команде, и ломает меню режимов.
                                        reason = 'Команда ещё не создана; PULL_INFO до CREATE пропущен'
                                    if reason:
                                        capture.record('team_skipped', code=hex(code), reason=reason, **info)
                                    else:
                                        if code == 0x701d:
                                            team['body'] = team_body(team['uid'], body, nickname)
                                        stamp = (clock['stamp'] + int((time.monotonic()-clock['at'])*25)) & 0xffffffff
                                        reply_code = 0x701e if code == 0x701d else 0x7030
                                        response = server_message(reply_code, team['body'], stamp, key)
                                        async with outgoing:
                                            writer.write(response)
                                            capture.record('data', response, direction='server_to_client', origin='team_probe', **info)
                                            await writer.drain()
                                        totals['team_replies'] += 1
                                        capture.record('team_reply', request_code=hex(code), code=hex(reply_code), payload_length=len(team['body']), **info)
                                    status()
                            if match_enabled:
                                message = client_message(frame, key)
                                if message and message[0] in (0x6e29, 0x6e2b):
                                    code, uid, body = message
                                    reason = None
                                    claimed = uid if uid >= 2**32 else None
                                    if not team['uid']:
                                        reason = 'Нет ENTER_GAME_RSP'
                                    elif claimed is not None and claimed != team['uid']:
                                        reason = 'UID не совпал с ENTER_GAME_RSP'
                                    elif not enabled['server_to_client'] or clock['stamp'] is None:
                                        reason = 'Нет проверенного серверного потока'
                                    elif team['body'] is None and not (
                                            training_enabled and team['novice_sent'] and
                                            ((code == 0x6e29 and len(body) == 20) or
                                             (code == 0x6e2b and team['training']))):
                                        reason = 'Команда ещё не создана'
                                    elif len(body) != (20 if code == 0x6e29 else 1):
                                        reason = 'Непроверенная длина запроса подбора'
                                    if reason:
                                        capture.record('match_skipped', code=hex(code), reason=reason, **info)
                                    else:
                                        # Официальный 6e2a: type/result/estimate-seconds, 6e2c: result.
                                        if code == 0x6e29:
                                            match_type = struct.unpack_from('>I', body)[0]
                                            payload = struct.pack('>III', match_type, 0, estimate)
                                            reply_code = 0x6e2a
                                            # Что именно клиент хочет запустить:
                                            # (режим, ?, перспектива, тип, карта).
                                            # Режим: 1 - Solo, 4 - Squad.
                                            # Перспектива: 1 - TPS, 2 - FPP.
                                            # Тип: 1 - обычный, 2 - тренировка.
                                            requested = struct.unpack('>5I', body)
                                            team['requested'] = requested
                                            capture.record('match_request', match_type=match_type,
                                                           mode={1: 'Solo', 4: 'Squad'}.get(requested[0], requested[0]),
                                                           perspective={1: 'TPS', 2: 'FPP'}.get(requested[2], requested[2]),
                                                           match_kind={1: 'normal', 2: 'training'}.get(requested[3], requested[3]),
                                                           map_id=requested[4],
                                                           words=list(requested), **info)
                                        else:
                                            payload = struct.pack('>I', 0)
                                            reply_code = 0x6e2c
                                        stamp = (clock['stamp'] + int((time.monotonic()-clock['at'])*25)) & 0xffffffff
                                        response = server_message(reply_code, payload, stamp, key)
                                        async with outgoing:
                                            writer.write(response)
                                            capture.record('data', response, direction='server_to_client', origin='match_probe', **info)
                                            await writer.drain()
                                        if code == 0x6e29:
                                            team['training'] = team['body'] is None
                                            # Адрес и ответ JOIN принадлежат одному подбору,
                                            # а не всему TCP-соединению. Новый принятый поиск
                                            # после ReturnLobby должен снова выдать D77/D76.
                                            join_state.update(sent=False, replied=False)
                                        team['generation'] += 1
                                        team['searching'] = code == 0x6e29
                                        if code == 0x6e29 and found_delay is not None:
                                            pumps.append(asyncio.create_task(notify_found(team['generation'])))
                                        totals['match_replies'] += 1
                                        capture.record('match_reply', request_code=hex(code), code=hex(reply_code), payload_length=len(payload), **info)
                                    status()
                            if team_enabled:
                                message = client_message(frame, key)
                                if message and message[0] in CUSTOM_ROOM_MESSAGES:
                                    # Кастомная комната: список, создание, выход, позиция.
                                    code, uid, body = message
                                    reply_code, decoder = CUSTOM_ROOM_MESSAGES[code]
                                    reason = None
                                    payload = None
                                    parsed = {}
                                    claimed = uid if uid >= 2**32 else None
                                    if not team['uid']:
                                        reason = 'Нет ENTER_GAME_RSP'
                                    elif claimed is not None and claimed != team['uid']:
                                        reason = 'UID не совпал с ENTER_GAME_RSP'
                                    elif not enabled['server_to_client'] or clock['stamp'] is None:
                                        reason = 'Нет проверенного серверного потока'
                                    else:
                                        try:
                                            parsed = decoder(body)
                                            team['nickname'] = (players[connection].get('nickname')
                                                                or getattr(args, 'team_nickname', 'Player'))
                                            outputs = custom_room_messages(code, body, parsed, team)
                                            stamp = (clock['stamp'] + int((time.monotonic()-clock['at'])*25)) & 0xffffffff
                                            responses = [server_message(out_code, payload, stamp, key)
                                                         for out_code, payload in outputs]
                                        except (ValueError, struct.error) as error:
                                            reason = str(error)
                                    if reason:
                                        capture.record('custom_room_skipped', code=hex(code), reason=reason, **info)
                                    else:
                                        if code == 0x736f:
                                            # Панель комнаты XVersion отбрасывает
                                            # ранние ответы списка: 100 мс.
                                            await asyncio.sleep(0.10)
                                        async with outgoing:
                                            for response in responses:
                                                writer.write(response)
                                                capture.record('data', response, direction='server_to_client', origin='custom_room_probe', **info)
                                            await writer.drain()
                                        totals['custom_room_replies'] += len(responses)
                                        capture.record('custom_room_request', code=hex(code),
                                                       reply=hex(reply_code), pushes=len(outputs) - 1,
                                                       variant=team.get('custom_variant'), **parsed, **info)
                                    status()
                            join = current_join(team['requested'][4] if team['requested'] else None)
                            if join is not None:
                                message = client_message(frame, key)
                                if message and message[0] == 0xd75:
                                    code, uid, body = message
                                    totals['join_requests'] += 1
                                    instance_id = decode_join_instance_request(body)
                                    reason = None
                                    claimed = uid if uid >= 2**32 else None
                                    if not team['uid']:
                                        reason = 'Нет ENTER_GAME_RSP'
                                    elif claimed is not None and claimed != team['uid']:
                                        reason = 'UID не совпал с ENTER_GAME_RSP'
                                    elif not join_state['sent'] or instance_id != join[0]:
                                        reason = 'Не совпал instance ID отправленного уведомления'
                                    elif join_state['replied']:
                                        reason = 'Повторный JOIN_INSTANCE_REQ'
                                    elif not enabled['server_to_client'] or clock['stamp'] is None:
                                        reason = 'Нет проверенного серверного потока'
                                    if reason:
                                        capture.record('join_skipped', reason=reason, **info)
                                    else:
                                        stamp = (clock['stamp'] + int((time.monotonic()-clock['at'])*25)) & 0xffffffff
                                        response = server_message(0xd76, join[2], stamp, key)
                                        async with outgoing:
                                            writer.write(response)
                                            join_state['replied'] = True
                                            capture.record('data', response, direction='server_to_client', origin='join_probe', **info)
                                            await writer.drain()
                                        totals['join_responses'] += 1
                                        capture.record('join_response', instance_id=instance_id, synthetic=True, **info)
                                    status()
                            counter = client_heartbeat(frame, key)
                            if counter is None:
                                continue
                            totals['heartbeat_requests'] += 1
                            capture.record('heartbeat_request', counter=counter, **info)
                            if args.reply and enabled['server_to_client'] and clock['stamp'] is not None and counter != last_counter:
                                elapsed = time.monotonic()-clock['at']
                                stamp = (clock['stamp'] + int(elapsed*25)) & 0xffffffff
                                response = heartbeat_reply(counter, stamp, key)
                                async with outgoing:
                                    writer.write(response)
                                    capture.record('data', response, direction='server_to_client', origin='heartbeat_probe', **info)
                                    await writer.drain()
                                last_counter = counter
                                totals['heartbeat_replies'] += 1
                                capture.record('heartbeat_reply', counter=counter, stamp=stamp, **info)
                            elif args.reply and (not enabled['server_to_client'] or clock['stamp'] is None):
                                capture.record('heartbeat_skipped', reason='Нет проверенного серверного потока', **info)
                            status()
                    except (ValueError, struct.error) as exc:
                        # Ошибка анализа выключает инъекцию направления, но не пересылку.
                        enabled[direction] = False
                        totals['inspection_errors'] += 1
                        capture.record('inspection_error', direction=direction, error=str(exc), **info)
                        status()
                if direction == 'server_to_client' and clock_stream is not None:
                    clock_stream.finish()
                if direction == 'server_to_client' and actor_stream is not None:
                    actor_stream.finish()
                if destination.can_write_eof():
                    destination.write_eof()
                capture.record('eof', direction=direction, **info)

            pumps = [asyncio.create_task(pump(reader, upstream, 'client_to_server')),
                     asyncio.create_task(pump(up_reader, writer, 'server_to_client'))]
            await asyncio.gather(*pumps)
        except (OSError, asyncio.TimeoutError, ValueError) as exc:
            capture.record('connection_error', error=str(exc), **info)
        finally:
            for pump_task in pumps:
                pump_task.cancel()
            await asyncio.gather(*pumps, return_exceptions=True)
            for stream in (writer, upstream):
                if stream:
                    stream.close()
                    try:
                        await stream.wait_closed()
                    except OSError:
                        pass
            capture.record('disconnect', **info)
            tasks.discard(task)
            players.pop(connection, None)
            status()

    try:
        server = await asyncio.start_server(handle, '127.0.0.1', args.port)
        async with server:
            binding = server.sockets[0].getsockname()
            capture.record('ready', bindings={'tcp': binding},
                           upstream=['127.0.0.1', args.upstream_port] if not local_lobby_enabled else 'local',
                           local_lobby=local_lobby_enabled, users=len(registry),
                           reply_enabled=args.reply)
            status()
            if ready:
                ready.set_result((binding, capture.directory))
            if args.duration:
                try:
                    await asyncio.wait_for(stop.wait(), args.duration)
                except asyncio.TimeoutError:
                    pass
            else:
                await stop.wait()
    finally:
        for task in list(tasks):
            task.cancel()
        if tasks:
            await asyncio.gather(*list(tasks), return_exceptions=True)
        status()
        state = json.loads((capture.directory/'status.json').read_text())
        state['state'] = 'stopped'
        (capture.directory/'status.json').write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding='utf-8')
        capture.record('stopped', **totals)
        capture.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--local-cosmetics-config', type=Path, help='Локальный каталог владения скинами оружия2022')
    parser.add_argument('--actor-uid',type=lambda value:int(value,0),help='Явный UID одного локального клиента в ENTER_GAME32B; не multiplayer/профиль аккаунта')
    parser.add_argument('--local-server-clock', action='store_true', help='Заменить архивный UNIX timestamp первого lobby1f5f текущим временем')
    parser.add_argument('--session-key-file', required=True, type=Path)
    parser.add_argument('--reply', action='store_true', help='Добавлять экспериментальные ответы 0x1f75')
    parser.add_argument('--team-reply', action='store_true', help='Экспериментальные CREATE/PULL_INFO ответы одного участника')
    parser.add_argument('--match-reply', action='store_true', help='Экспериментальные начало/отмена подбора; требует team-reply')
    parser.add_argument('--match-found-delay', type=float, help='Через N секунд отправить тестовый MATCH_SYNC=0; требует match-reply')
    parser.add_argument('--match-estimate', type=int, default=5,
                        help='Оценка ожидания в секундах, U32 (локальный сервер отвечает сразу)')
    parser.add_argument('--training-reply', action='store_true', help='Разрешить наблюдённый Solo Training без CREATE; требует match-reply и novice-state=1')
    parser.add_argument('--join-instance-config', type=Path, help='Явные синтетические NOTIFY/RSP для loopback опыта после Training Match Found')
    parser.add_argument('--novice-state', type=int, choices=(0, 1, 2), help='Тестовый MATCH_NOVICE_SYNC после ENTER_GAME; требует team-reply')
    parser.add_argument('--team-nickname', default='Player', help='Имя участника в экспериментальном ответе')
    parser.add_argument('--profile-nickname', default='',
                        help='Экспериментально: заменить имя lobby-профиля 0x2ef; пусто отключает')
    parser.add_argument('--auto-match-seconds', type=float,
                        help='start the training match automatically after N seconds without a client search request')
    parser.add_argument('--port', type=int, default=8001)
    parser.add_argument('--upstream-port', type=int, default=9001)
    parser.add_argument('--local-lobby', action='store_true',
                        help='Отвечать базовые пакеты лобби внутри процесса (внешний сервер на C# не нужен)')
    parser.add_argument('--lobby-ck', type=Path, default=ROOT/'private/lobby-ck.bin')
    parser.add_argument('--users-registry', type=Path,
                        help='Реестр uid -> профиль (users/registry.json)')
    parser.add_argument('--duration', type=float, default=180)
    parser.add_argument('--output', type=Path, default=ROOT/'captures')
    parser.add_argument('--capture-dir', type=Path,
                        help='Точная папка журналов сервиса (без подпапки по запуску)')
    args = parser.parse_args()
    if not 0 <= args.port <= 65535 or not 1 <= args.upstream_port <= 65535 or args.port == args.upstream_port or args.duration < 0:
        parser.error('Некорректные порты или длительность')
    if args.actor_uid is not None and not 0 < args.actor_uid < 2**64:
        parser.error('actor-uid требует ненулевой U64')
    if args.training_reply and (not args.match_reply or args.novice_state != 1):
        parser.error('--training-reply требует --match-reply и --novice-state 1')
    if args.novice_state is not None and not args.team_reply:
        parser.error('--novice-state требует --team-reply')
    if args.match_found_delay is not None and (not args.match_reply or args.match_found_delay < 0):
        parser.error('--match-found-delay требует --match-reply и неотрицательную задержку')
    if args.match_reply and not args.team_reply:
        parser.error('--match-reply требует --team-reply')
    if not 0 <= args.match_estimate <= 0xffffffff:
        parser.error('--match-estimate должен быть U32')
    try:
        asyncio.run(serve(args))
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
