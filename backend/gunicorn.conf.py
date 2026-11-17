"""gunicorn reads this file from the working directory. Access log: the date first, then the real client (X-Real-IP from nginx; gunicorn itself sees only 127.0.0.1)."""
import time

from gunicorn.glogging import Logger


class DateFirstLogger(Logger):
    def atoms(self, resp, req, environ, request_time):
        a = super().atoms(resp, req, environ, request_time)
        a['t'] = time.strftime('%Y-%m-%d %H:%M:%S')
        a['ip'] = environ.get('HTTP_X_REAL_IP') or a['h']
        return a


logger_class = DateFirstLogger
access_log_format = '%(t)s %(ip)s "%(r)s" %(s)s %(b)s "%(a)s"'
