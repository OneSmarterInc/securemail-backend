"""Request-local numeric timings. Never collect arguments, SQL or payloads."""

import json
import logging
import time
from contextvars import ContextVar
from functools import wraps

metrics = ContextVar("performance_metrics", default=None)


def timed(name):
    def decorate(function):
        @wraps(function)
        def call(*args, **kwargs):
            current = metrics.get()
            if current is None:
                return function(*args, **kwargs)
            start = time.perf_counter()
            try:
                return function(*args, **kwargs)
            finally:
                current[name + "_ms"] = (
                    current.get(name + "_ms", 0) + (time.perf_counter() - start) * 1000
                )
                current[name + "_calls"] = current.get(name + "_calls", 0) + 1

        return call

    return decorate


class PerformanceMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        from django.conf import settings
        from django.db import connection

        if not settings.PERFORMANCE_TIMINGS:
            return self.get_response(request)
        current = {}
        token = metrics.set(current)
        start = time.perf_counter()
        status = 500

        @timed("database")
        def execute(run, sql, params, many, context):
            return run(sql, params, many, context)

        try:
            with connection.execute_wrapper(execute):
                response = self.get_response(request)
                status = response.status_code
                return response
        finally:
            metrics.reset(token)
            duration = (time.perf_counter() - start) * 1000
            if duration >= settings.PERFORMANCE_LOG_THRESHOLD_MS:
                match = getattr(request, "resolver_match", None)
                logging.getLogger("securemail.performance").info(
                    json.dumps(
                        {
                            "event": "request.timing",
                            "endpoint": getattr(
                                getattr(match, "func", None), "__name__", "unresolved"
                            ),
                            "request_id": getattr(request, "request_id", ""),
                            "status": status,
                            "total_ms": round(duration, 2),
                            **{key: round(value, 2) for key, value in current.items()},
                        }
                    )
                )
