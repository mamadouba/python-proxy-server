# Server
VERSION = "http-proxy/1.0"
HOST = 'localhost'
PORT = 12345
TLS = False
MAX_CONN = 1000
READ_TIMEOUT = 60
LOOP_DELAY = 0.0001
BUFFER_SIZE = 4096

# SSL 
KEYFILE =  'key.pem'
CERTFILE = 'cert.pem'
CAFILE = ''

# Cache
CACHE_SIZE = 100
CACHE_EXPIRE = 300

# Logging
DEBUG = True
ERROR_LOG = 'error.log'
ACCESS_LOG = 'access.log'

# Auth
JWT_CER_FILE = ''
JWT_KEY_FILE = ''

# Backends
UPSTREAMS = ["localhost:5000", "localhost:5001"]

# Locations path
LOCATIONS = [
    {
        "path": "/login",
        "auth": False
    },
    {
        "path": "/register",
        "auth": False
    },
    {
        "path": "/api",
        "auth": True
    }
]