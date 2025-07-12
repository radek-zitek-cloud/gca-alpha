"""
Logging configuration for the API Gateway.

This module provides centralized logging configuration with support for
structured logging, different log levels, and multiple output formats.
"""

import logging
import logging.config
import sys
from typing import Dict, Any
from pathlib import Path


def get_logging_config(
    log_level: str = "INFO",
    log_format: str = "json",
    log_file: str = None,
    enable_access_log: bool = True
) -> Dict[str, Any]:
    """
    Get logging configuration dictionary.
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_format: Log format ('json' or 'text')
        log_file: Optional log file path
        enable_access_log: Whether to enable HTTP access logging
        
    Returns:
        Logging configuration dictionary
    """
    
    # Check if python-json-logger is available
    try:
        import pythonjsonlogger.jsonlogger
        json_formatter_available = True
    except ImportError:
        json_formatter_available = False
    
    # Base formatter configurations
    formatters = {
        "default": {
            "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            "datefmt": "%Y-%m-%d %H:%M:%S"
        },
        "detailed": {
            "format": "%(asctime)s - %(name)s - %(levelname)s - %(module)s:%(lineno)d - %(message)s",
            "datefmt": "%Y-%m-%d %H:%M:%S"
        }
    }
    
    # Add JSON formatter only if available
    if json_formatter_available:
        formatters["json"] = {
            "()": "pythonjsonlogger.jsonlogger.JsonFormatter",
            "format": "%(asctime)s %(name)s %(levelname)s %(module)s %(lineno)d %(message)s"
        }
    else:
        # Fallback to detailed format if JSON formatter is not available
        formatters["json"] = formatters["detailed"]
    
    # Choose formatter based on format preference
    if log_format == "json":
        formatter_name = "json"
    else:
        formatter_name = "detailed"
    
    # Base handler configurations
    handlers = {
        "console": {
            "class": "logging.StreamHandler",
            "level": log_level,
            "formatter": formatter_name,
            "stream": sys.stdout
        }
    }
    
    # Add file handler if log file is specified
    if log_file:
        handlers["file"] = {
            "class": "logging.handlers.RotatingFileHandler",
            "level": log_level,
            "formatter": formatter_name,
            "filename": log_file,
            "maxBytes": 10485760,  # 10MB
            "backupCount": 5,
            "encoding": "utf8"
        }
    
    # Logger configurations
    loggers = {
        "": {  # Root logger
            "level": log_level,
            "handlers": list(handlers.keys()),
            "propagate": False
        },
        "uvicorn": {
            "level": log_level,
            "handlers": list(handlers.keys()),
            "propagate": False
        },
        "uvicorn.error": {
            "level": log_level,
            "handlers": list(handlers.keys()),
            "propagate": False
        },
        "fastapi": {
            "level": log_level,
            "handlers": list(handlers.keys()),
            "propagate": False
        },
        "app": {  # Application logger
            "level": log_level,
            "handlers": list(handlers.keys()),
            "propagate": False
        }
    }
    
    # Add access logger if enabled
    if enable_access_log:
        loggers["uvicorn.access"] = {
            "level": "INFO",
            "handlers": list(handlers.keys()),
            "propagate": False
        }
    
    return {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": formatters,
        "handlers": handlers,
        "loggers": loggers
    }


def setup_logging(
    log_level: str = "INFO",
    log_format: str = "text",
    log_file: str = None,
    enable_access_log: bool = True
) -> None:
    """
    Setup logging configuration.
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_format: Log format ('json' or 'text')
        log_file: Optional log file path
        enable_access_log: Whether to enable HTTP access logging
    """
    config = get_logging_config(
        log_level=log_level,
        log_format=log_format,
        log_file=log_file,
        enable_access_log=enable_access_log
    )
    
    logging.config.dictConfig(config)


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance with the specified name.
    
    Args:
        name: Logger name (typically __name__)
        
    Returns:
        Logger instance
    """
    return logging.getLogger(name)


class StructuredLogger:
    """
    Structured logger for consistent log message formatting.
    
    This class provides methods for logging structured data with
    consistent field names and formats.
    """
    
    def __init__(self, name: str):
        """Initialize structured logger.
        
        Args:
            name: Logger name
        """
        self.logger = get_logger(name)
    
    def log_request(
        self,
        method: str,
        path: str,
        status_code: int,
        response_time: float,
        client_ip: str = None,
        user_agent: str = None,
        **kwargs
    ):
        """Log HTTP request information.
        
        Args:
            method: HTTP method
            path: Request path
            status_code: Response status code
            response_time: Response time in milliseconds
            client_ip: Client IP address
            user_agent: User agent string
            **kwargs: Additional fields to log
        """
        log_data = {
            "event": "http_request",
            "method": method,
            "path": path,
            "status_code": status_code,
            "response_time_ms": response_time,
        }
        
        if client_ip:
            log_data["client_ip"] = client_ip
        if user_agent:
            log_data["user_agent"] = user_agent
        
        log_data.update(kwargs)
        
        # Determine log level based on status code
        if status_code >= 500:
            self.logger.error("HTTP request", extra=log_data)
        elif status_code >= 400:
            self.logger.warning("HTTP request", extra=log_data)
        else:
            self.logger.info("HTTP request", extra=log_data)
    
    def log_service_call(
        self,
        service_name: str,
        endpoint: str,
        method: str,
        status_code: int,
        response_time: float,
        success: bool,
        error: str = None,
        **kwargs
    ):
        """Log upstream service call information.
        
        Args:
            service_name: Name of the upstream service
            endpoint: Service endpoint URL
            method: HTTP method
            status_code: Response status code
            response_time: Response time in milliseconds
            success: Whether the call was successful
            error: Error message if call failed
            **kwargs: Additional fields to log
        """
        log_data = {
            "event": "service_call",
            "service_name": service_name,
            "endpoint": endpoint,
            "method": method,
            "status_code": status_code,
            "response_time_ms": response_time,
            "success": success,
        }
        
        if error:
            log_data["error"] = error
        
        log_data.update(kwargs)
        
        if success:
            self.logger.info("Service call", extra=log_data)
        else:
            self.logger.error("Service call failed", extra=log_data)
    
    def log_health_check(
        self,
        service_name: str,
        instance_id: str,
        healthy: bool,
        response_time: float = None,
        error: str = None,
        **kwargs
    ):
        """Log health check information.
        
        Args:
            service_name: Name of the service
            instance_id: Service instance ID
            healthy: Whether the instance is healthy
            response_time: Health check response time in milliseconds
            error: Error message if health check failed
            **kwargs: Additional fields to log
        """
        log_data = {
            "event": "health_check",
            "service_name": service_name,
            "instance_id": instance_id,
            "healthy": healthy,
        }
        
        if response_time is not None:
            log_data["response_time_ms"] = response_time
        if error:
            log_data["error"] = error
        
        log_data.update(kwargs)
        
        if healthy:
            self.logger.debug("Health check passed", extra=log_data)
        else:
            self.logger.warning("Health check failed", extra=log_data)
    
    def info(self, message: str, **kwargs):
        """Log info message with structured data."""
        self.logger.info(message, extra=kwargs)
    
    def warning(self, message: str, **kwargs):
        """Log warning message with structured data."""
        self.logger.warning(message, extra=kwargs)
    
    def error(self, message: str, **kwargs):
        """Log error message with structured data."""
        self.logger.error(message, extra=kwargs)
    
    def debug(self, message: str, **kwargs):
        """Log debug message with structured data."""
        self.logger.debug(message, extra=kwargs)


# Global structured logger instance for the application
app_logger = StructuredLogger("app")
