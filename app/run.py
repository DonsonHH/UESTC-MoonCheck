import logging
import os
from pathlib import Path
from waitress import serve
from app import create_app

def main():
    # Hold a process-level file lock for the lifetime of the service. One scheduler
    # owns one database; an accidental second launch must not submit duplicate jobs.
    folder = Path(os.environ.get('MOONCHECK_DATA_DIR') or Path(__file__).parent / 'data')
    folder.mkdir(parents=True, exist_ok=True)
    handle = (folder / 'server.lock').open('a+b')
    try:
        if os.name == 'nt':
            import msvcrt
            if handle.seek(0, 2) == 0:
                handle.write(b'0')
                handle.flush()
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        raise SystemExit('MoonCheck 已在运行：同一个数据目录只允许一个服务进程。')
    (folder / 'server.pid').write_text(str(os.getpid()), encoding='ascii')
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s %(message)s')
    app = create_app(folder, start_scheduler=True)
    host = os.environ.get('MOONCHECK_HOST', '127.0.0.1')
    port = int(os.environ.get('MOONCHECK_PORT', '8765'))
    print(f'MoonCheck: http://{host}:{port}', flush=True)
    try:
        serve(app, host=host, port=port, threads=8)
    finally:
        app.extensions['service'].close()
        (folder / 'server.pid').unlink(missing_ok=True)
        handle.close()

if __name__ == '__main__':
    main()
