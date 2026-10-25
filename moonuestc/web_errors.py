class WebError(Exception):
    def __init__(self, status, code, message, *, retry_after=None):
        super().__init__(code)
        self.status, self.code, self.message = status, code, message
        self.retry_after=retry_after
