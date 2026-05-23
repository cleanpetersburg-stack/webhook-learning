# Пример проверки подписи вебхука

```python
import hmac
import hashlib
import json

def verify_signature(secret, body, signature_header, timestamp):
    """
    Проверяет подпись вебхука.
    
    Аргументы:
        secret: str - секретный ключ подписчика
        body: dict - тело запроса
        signature_header: str - значение заголовка X-Signature
        timestamp: str - значение заголовка X-Timestamp
    
    Возвращает:
        bool: True если подпись верна, иначе False
    """
    # Формируем строку для подписи
    payload = f"{timestamp}.{json.dumps(body, sort_keys=True)}"
    
    # Вычисляем HMAC-SHA256
    expected = hmac.new(
        key=secret.encode('utf-8'),
        msg=payload.encode('utf-8'),
        digestmod=hashlib.sha256
    ).hexdigest()
    
    # Сравниваем (защита от timing attack)
    return hmac.compare_digest(
        f"sha256={expected}",
        signature_header
    )

# Пример использования
if __name__ == "__main__":

    secret = "whsec_test123"
    body = {"event": "order.created", "id": 123}
    timestamp = "1698765432"
    signature = "sha256=5e8c7b4a3f2d1e0b9a8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a"
    
    is_valid = verify_signature(secret, body, signature, timestamp)
    print(f"Подпись верна: {is_valid}")
```

## Идемпотентность: проверка дублей

```python
import redis
from datetime import timedelta

class WebhookReceiver:
    def __init__(self, redis_client):
        self.redis = redis_client
        self.ttl_days = 30
    
    def is_processed(self, event_id, recipient_url):
        """Проверяет, не обрабатывалось ли уже событие"""
        key = f"webhook:processed:{recipient_url}:{event_id}"
        return self.redis.exists(key)
    
    def mark_processed(self, event_id, recipient_url):
        """Отмечает событие как обработанное"""
        key = f"webhook:processed:{recipient_url}:{event_id}"
        self.redis.setex(key, timedelta(days=self.ttl_days), "1")
```
