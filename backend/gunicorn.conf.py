"""gunicorn reads this file from the working directory. Access log: the date first, then the real client (X-Real-IP from nginx; gunicorn itself sees only 127.0.0.1)."""
import time

from gunicorn.glogging import Logger

ACCESS_FORMAT = '%(t)s %(ip)s "%(r)s" %(s)s %(b)s "%(a)s"'


class DateFirstLogger(Logger):
    def __init__(self, cfg):
        cfg.set('access_log_format', ACCESS_FORMAT)  # also over a --access-logformat left in the supervisor command
        super().__init__(cfg)

    def atoms(self, resp, req, environ, request_time):
        a = super().atoms(resp, req, environ, request_time)
        a['t'] = time.strftime('%Y-%m-%d %H:%M:%S')
        a['ip'] = environ.get('HTTP_X_REAL_IP') or a['h']
        return a


logger_class = DateFirstLogger
