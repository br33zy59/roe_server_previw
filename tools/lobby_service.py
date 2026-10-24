"""Служба лобби: игровой TCP (8001) и свой HTTP-API (8010).

Лобби - постоянная служба. Комнату в нём регистрирует room_manager:
`GET /api/room?route=127.0.0.1:18001&map_id=16010&instance_id=1`, после
чего лобби отдаёт клиенту адрес комнаты в JOIN_INSTANCE.

Конфиг: `config/services/lobby.json` (пути относительно корня репозитория).
"""
from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import secrets
import sys
import threading
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
sys.path.insert(0, str(ROOT / 'server' / 'directory'))
from roe_join_instance_2022 import (
    JoinInstanceNotification,
    JoinInstanceResponse,
    encode_join_instance_notification,
    encode_join_instance_response,
)

DEFAULT_CONFIG = ROOT / 'config' / 'services' / 'lobby.json'


def load_config(path):
    data = json.loads(Path(path).read_text(encoding='utf-8'))
    if not isinstance(data, dict):
        raise ValueError('конфиг лобби должен быть объектом')
    return data


def resolve(value):
    path = Path(str(value)).expanduser()
    return path if path.is_absolute() else ROOT / path


class Tee:
    """Дублирует вывод в консоль и в файл журнала запуска."""

    def __init__(self, *streams):
        self.streams = streams

    def write(self, data):
        for stream in self.streams:
            try:
                stream.write(data)
                stream.flush()
            except (OSError, ValueError):
                pass

    def flush(self):
        for stream in self.streams:
            try:
                stream.flush()
            except (OSError, ValueError):
                pass


class LobbyState:
    """Общее состояние службы: зарегистрированные комнаты и файлы журналов."""

    def __init__(self, config):
        self.config = config
        self.join_path = resolve(config['join_config'])
        self.root = resolve(config['capture_dir'])
        self.capture_dir = self.root
        self.rooms = {}
        self.default_room = None
        self.lock = threading.Lock()

    def register_room(self, route, map_id, instance_id, mode=None):
        with self.lock:
            room = {'route': route, 'map_id': int(map_id), 'instance_id': int(instance_id),
                    'mode': mode, 'registered_at': dt.datetime.now(dt.timezone.utc).isoformat()}
            self.rooms[int(map_id)] = room
            if self.default_room is None or int(map_id) == 16010:
                # Комната карты 16010 (Dion) - основная.
                self.default_room = room
            self._write_join(self.default_room)
            return room

    def unregister_room(self, map_id):
        """Убирает комнату (менеджер комнат сообщает об остановке)."""
        with self.lock:
            room = self.rooms.pop(int(map_id), None)
            if room is not None and self.default_room is not None \
                    and self.default_room.get('map_id') == int(map_id):
                self.default_room = next(iter(self.rooms.values()), None)
            if self.default_room is not None:
                self._write_join(self.default_room)
            return room

    def room_for_map(self, map_id=None):
        """Комната под запрошенную карту: точная, иначе основная."""
        with self.lock:
            if map_id is not None and int(map_id) in self.rooms:
                return self.rooms[int(map_id)]
            return self.default_room

    def _join_value(self, room, client_map_id=None):
        map_id = int(client_map_id) if client_map_id is not None else int(room['map_id'])
        return {
            'delay_after_found': int(self.config.get('match', {}).get('join_delay', 1)),
            'notification': {
                'unknown_00': 0,
                'instance_id': int(room['instance_id']),
                'unknown_0c': 0,
                'unknown_14': 0,
                'unknown_18': 0,
                'unknown_20': 1,
                'unknown_28': map_id,
                'unknown_2c': 0,
            },
            'response': {
                'result': 0,
                'route': room['route'],
                'block_88': '00000000000000000000000000000000',
                'block_98': '00000000000000000000000000000000',
                'connection_id_a8': int(room['instance_id']),
                'unknown_ac': 0,
                'flag_b0': 0,
            },
        }

    def _write_join(self, room):
        if room is None:
            return
        value = self._join_value(room)
        self.join_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.join_path.with_suffix('.tmp')
        temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        temporary.replace(self.join_path)

    def join_provider(self, map_id=None):
        """Данные JOIN для запрошенной карты (в том же процессе, что и прокси)."""
        room = self.room_for_map(map_id)
        if room is None:
            return None
        value = self._join_value(room, client_map_id=map_id)
        temporary = self.join_path.with_suffix('.tmp')
        temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        temporary.replace(self.join_path)
        notification = JoinInstanceNotification(**value['notification'])
        response = dict(value['response'])
        prefix, address, port = response['route'].split(':')
        response['route'] = response['route'].encode('ascii')
        for name in ('block_88', 'block_98'):
            response[name] = bytes.fromhex(response[name])
        response = JoinInstanceResponse(**response)
        return (int(value['notification']['instance_id']),
                encode_join_instance_notification(notification),
                encode_join_instance_response(response),
                int(value['delay_after_found']))

    def handle(self, path, query):
        if path in ('', '/', '/api', '/api/'):
            return {
                'ok': True,
                'service': 'roe-lobby',
                'endpoints': [
                    '/api/status',
                    '/api/players',
                    '/api/room?route=127.0.0.1:18001&map_id=16010&instance_id=1',
                ],
            }
        if path in ('/api/status', '/api/lobby'):
            return self.status()
        if path == '/api/players':
            return {'ok': True, 'players': self.status()['players']}
        if path == '/api/room':
            route = (query.get('route') or [''])[0].strip()
            map_id = (query.get('map_id') or ['0'])[0].strip()
            instance_id = (query.get('instance_id') or ['1'])[0].strip()
            mode = (query.get('mode') or [''])[0].strip() or None
            if not route:
                raise ValueError('route is required')
            if not route.replace(':', '').isdigit() and ':' not in route:
                raise ValueError('route must look like 0:host:port')
            try:
                room = self.register_room(route, int(map_id), int(instance_id), mode)
            except (TypeError, ValueError) as error:
                raise ValueError('map_id and instance_id must be integers') from error
            return {'ok': True, 'room': room, 'join_config': str(self.join_path)}
        if path in ('/api/room/unregister', '/api/room/remove'):
            map_id = (query.get('map_id') or [''])[0].strip()
            try:
                removed = self.unregister_room(int(map_id))
            except ValueError:
                raise ValueError('map_id must be an integer')
            return {'ok': True, 'removed': removed, 'rooms': [dict(row) for row in self.rooms.values()]}
        raise ValueError('unknown endpoint')

    def status(self):
        counters = {}
        status_file = self.capture_dir / 'status.json'
        if status_file.is_file():
            try:
                counters = json.loads(status_file.read_text(encoding='utf-8'))
            except (OSError, ValueError):
                counters = {}
        with self.lock:
            room = dict(self.default_room) if self.default_room else None
            rooms = [dict(value) for value in self.rooms.values()]
        return {
            'ok': True,
            'service': 'roe-lobby',
            'room': room,
            'rooms': rooms,
            'players': counters.get('players', []),
            'counters': {key: value for key, value in counters.items() if key != 'players'},
            'join_config': str(self.join_path),
        }


class Handler(BaseHTTPRequestHandler):
    server_version = 'ROE-Lobby/1.0'

    def do_GET(self):
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query, keep_blank_values=True)
        try:
            result = self.server.lobby.handle(parsed.path, query)
            self.send_json(200, result)
        except Exception as error:
            self.send_json(400, {'ok': False, 'error': str(error)})

    def send_json(self, code, value):
        body = json.dumps(value, ensure_ascii=False, indent=2).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


class ApiServer(ThreadingHTTPServer):
    allow_reuse_address = False


def build_args(config, overrides):
    match = config.get('match', {})
    fallback = config.get('fallback', {}) or {}
    values = {
        'session_key_file': resolve(config['session_key_file']),
        'lobby_ck': resolve(config['lobby_ck']),
        'users_registry': resolve(config['users_registry']),
        'local_cosmetics_config': resolve(config['local_cosmetics']),
        'join_instance_config': resolve(config['join_config']),
        'port': int(config['port']),
        'local_lobby': True,
        'reply': True,
        'team_reply': True,
        'match_reply': True,
        'novice_state': 1,
        'training_reply': True,
        'match_found_delay': match.get('found_delay', 5),
        'match_estimate': match.get('estimate_seconds', 5),
        'team_nickname': config.get('team_nickname', 'Player'),
        'profile_nickname': fallback.get('nickname', ''),
        'actor_uid': int(str(fallback.get('actor_uid', '0x515bb1e1dd242c')), 0),
        'duration': 86400,
        'output': resolve(config['capture_dir']),
        'capture_dir': overrides.get('capture_dir'),
    }
    if match.get('auto_match_seconds') is not None:
        values['auto_match_seconds'] = match['auto_match_seconds']
    values.update(overrides)
    return type('Args', (), values)()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--config', type=Path, default=DEFAULT_CONFIG)
    parser.add_argument('--port', type=int, help='игровой TCP-порт')
    parser.add_argument('--api-port', type=int, help='порт HTTP-API лобби')
    parser.add_argument('--duration', type=float, default=86400)
    args = parser.parse_args(argv)

    config = load_config(args.config)
    overrides = {'duration': args.duration}
    if args.port:
        config['port'] = args.port
    if args.api_port:
        config['api_port'] = args.api_port
    state = LobbyState(config)

    # Папка запуска лобби: свои журналы, независимые от комнат.
    run_dir = state.root / (dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S')
                            + '-lobby-' + secrets.token_hex(3))
    run_dir.mkdir(parents=True, exist_ok=True)
    overrides['capture_dir'] = run_dir
    state.capture_dir = run_dir
    # Указатель на текущий запуск - в корне лобби, его читает room_manager.
    (state.root / 'current.json').write_text(json.dumps({
        'run': run_dir.name,
        'directory': str(run_dir),
        'packets_log': str(run_dir / 'packets.log'),
        'events_log': str(run_dir / 'events.jsonl'),
        'status': str(run_dir / 'status.json'),
        'service_log': str(run_dir / 'service.log'),
        'started_at': dt.datetime.now(dt.timezone.utc).isoformat(),
    }, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    # Журнал запуска службы - рядом с её данными.
    service_log = (run_dir / 'service.log').open('a', encoding='utf-8')
    sys.stdout = Tee(sys.stdout, service_log)
    sys.stderr = Tee(sys.stderr, service_log)

    api = ApiServer((config.get('host', '127.0.0.1'), int(config['api_port'])), Handler)
    api.lobby = state
    api_thread = threading.Thread(target=api.serve_forever, kwargs={'poll_interval': 0.5}, daemon=True)
    api_thread.start()
    print(json.dumps({'ok': True, 'service': 'roe-lobby', 'tcp': config['port'],
                      'api': f"http://{config.get('host', '127.0.0.1')}:{config['api_port']}/api/status"},
                     ensure_ascii=False), flush=True)

    service_args = build_args(config, overrides)
    # Прокси в этом же процессе спрашивает комнату под запрошенную карту.
    service_args.join_provider = state.join_provider
    from heartbeat_probe_2022 import serve
    try:
        asyncio.run(serve(service_args))
    except KeyboardInterrupt:
        pass
    finally:
        api.shutdown()
    return 0


if __name__ == '__main__':
    sys.exit(main())
