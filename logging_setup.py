import json, logging, logging.handlers, sys, os

class JsonFmt(logging.Formatter):
    def format(self, rec):
        base = {
          "ts": self.formatTime(rec, "%Y-%m-%dT%H:%M:%S"),
          "lvl": rec.levelname, "msg": rec.getMessage(),
          "logger": rec.name
        }
        if hasattr(rec, "extra"):
            base.update(rec.extra)
        return json.dumps(base)

def setup_logging(level="INFO", path="logs/malcrawl.log"):
    logger = logging.getLogger()
    logger.setLevel(level)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fh = logging.handlers.RotatingFileHandler(path, maxBytes=5_000_000, backupCount=3)
    sh = logging.StreamHandler(sys.stdout)
    fmt = JsonFmt()
    fh.setFormatter(fmt); sh.setFormatter(fmt)
    logger.addHandler(fh); logger.addHandler(sh)
