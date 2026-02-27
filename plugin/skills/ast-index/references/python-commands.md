# Python Commands Reference

ast-index supports parsing and indexing Python source files (`.py`), including Django/DRF framework analysis.

## Supported Elements

| Python Element | Symbol Kind | Example |
|----------------|-------------|---------|
| `class ClassName` | Class | `UserService` -> Class |
| `def function_name` | Function | `process_data` -> Function |
| `def _private_method` | Function | `_get_jwt` -> Function |
| `async def function_name` | Function | `fetch_user` -> Function |
| `@decorator` | Decorator | `@dataclass` -> Decorator |
| `@action(detail=True)` | Decorator | `@action` -> Decorator |
| `import module` | Import | `import os` -> Import |
| `from module import name` | Import | `from typing import List` -> Import |

## Core Commands

### Search Classes

Find Python class definitions:

```bash
ast-index class "Service"           # Find service classes
ast-index class "Handler"           # Find handler classes
ast-index search "Repository"       # Find repositories
```

### Search Functions

Find functions and async functions (including private `_methods`):

```bash
ast-index symbol "process"          # Find functions containing "process"
ast-index symbol "_get_jwt"         # Find private methods
ast-index callers "handle_request"  # Find callers of handle_request
ast-index usages "UserService"      # Find usages (including self._method() calls)
```

### File Analysis

Show file structure:

```bash
ast-index outline "service.py"      # Show classes and functions
ast-index imports "handler.py"      # Show all imports (including from X import Y)
```

## Django/DRF Commands

### py.routes

List all Django/DRF endpoints (requires `rebuild`):

```bash
ast-index py.routes                          # List all routes
ast-index py.routes --format json            # JSON output
ast-index py.routes -l 50                    # Limit results
```

Output includes: HTTP method, path pattern, handler, confidence, file:line.

### py.endpoint-trace

Trace endpoint -> handler -> serializer -> model -> settings chain:

```bash
ast-index py.endpoint-trace "/api/users/"                # Find by path pattern
ast-index py.endpoint-trace "/api/users/" --method GET   # Filter by HTTP method
ast-index py.endpoint-trace "/api/users/" --format json  # JSON output
```

Trace chain:
1. **Endpoint**: Django `path()`/`re_path()` or DRF `router.register()`
2. **Handler**: ViewSet/View class linked to endpoint
3. **Serializer**: serializer referenced in handler (via `serializer_class`)
4. **Model**: model from `Meta.model` in serializer
5. **Settings**: `settings.KEY`, `os.getenv()`, `env()` usages in handler

### py.model-impact

Show blast radius for a Django model (serializers -> handlers -> endpoints):

```bash
ast-index py.model-impact "User"                         # Find model impact
ast-index py.model-impact "Order" --format json          # JSON output
ast-index py.model-impact "Product" -l 10                # Limit model matches
```

Impact chain:
1. **Model**: Django model class (prefers `models.py` files)
2. **Serializers**: linked via `Meta.model` in serializer
3. **Handlers**: linked via `serializer_class` in ViewSet/View
4. **Endpoints**: linked via `router.register()` / `urlpatterns`

### py.setting-usage

Find usages of settings/environment variables:

```bash
ast-index py.setting-usage "DATABASE"                    # Substring search
ast-index py.setting-usage "API_KEY" --format json       # JSON output
ast-index py.setting-usage "SECRET" -l 20                # Limit results
```

Detected patterns:
- `settings.KEY` (Django settings)
- `os.getenv("KEY")` (environment)
- `os.environ.get("KEY")` (environment)
- `env("KEY")` / `config("KEY")` (django-environ/decouple)

## Bundle Command

Collect deterministic context packages by seed type. Useful for code review, impact analysis, and framework tracing.

```bash
# Endpoint seed: endpoint + handler + serializer + model + settings
ast-index bundle --seed-type endpoint --seed "/api/users/" --format json
ast-index bundle --seed-type endpoint --seed "orders" --method GET

# Model seed: model + serializers + handlers + endpoints
ast-index bundle --seed-type model --seed "User" --format json

# Setting seed: setting usages + handler symbols + endpoints
ast-index bundle --seed-type setting --seed "DATABASE_URL" --format json

# Symbol seed: definition + settings + related endpoints
ast-index bundle --seed-type symbol --seed "UserViewSet" --format json

# Budget control
ast-index bundle --seed-type model --seed "Order" --max-items 20 --max-files 5
```

Bundle item format: `{path, line, kind, name, reason, confidence}`.

Supported seed types: `endpoint`, `model`, `setting`, `symbol`.

## Example Workflow

```bash
# 1. Index Django/DRF project
cd /path/to/django/project
ast-index rebuild

# 2. Check index statistics
ast-index stats

# 3. List all API routes
ast-index py.routes

# 4. Trace a specific endpoint
ast-index py.endpoint-trace "/api/v1/users/"

# 5. Check model blast radius
ast-index py.model-impact "User"

# 6. Find all usages of a setting
ast-index py.setting-usage "DATABASE_URL"

# 7. Collect context bundle for review
ast-index bundle --seed-type endpoint --seed "/api/v1/users/" --format json

# 8. Find private methods
ast-index symbol "_get_jwt"
ast-index usages "_validate_token"

# 7. Show file structure
ast-index outline "views.py"
```

## Indexed Python Patterns

### Class Definition (including private methods)

```python
class AuthService:
    def __init__(self, secret: str):
        self._secret = secret

    def _get_jwt(self, user_id: int) -> str:
        return jwt.encode({"user_id": user_id}, self._secret)

    async def authenticate(self, request):
        token = self._get_jwt(request.user.id)
        return token
```

Indexed as:
- `AuthService` [class]
- `__init__` [function]
- `_get_jwt` [function]
- `authenticate` [function]

Refs: `self._get_jwt()` call appears in refs for `_get_jwt`.

### Django/DRF Decorators

```python
@action(detail=True, methods=["post"])
def activate(self, request, pk=None):
    pass

@login_required
def dashboard(request):
    pass

@csrf_exempt
def webhook(request):
    pass
```

Indexed decorators: `@action`, `@api_view`, `@login_required`, `@csrf_exempt`, `@staticmethod`, `@classmethod`, `@abstractmethod`, `@cached_property`, `@celery.task`, and more.

### Django URL Patterns

```python
urlpatterns = [
    path("api/users/", UserListView.as_view(), name="users"),
    re_path(r"^api/v1/orders/$", order_list, name="orders"),
]

router = DefaultRouter()
router.register(r"users", UserViewSet, basename="user")
```

Extracted as py.routes with handler links.

### Serializer -> Model

```python
class UserSerializer(ModelSerializer):
    class Meta:
        model = User
        fields = "__all__"
```

Extracted link: `UserSerializer` -> `User` model.

### Settings/Environment

```python
host = settings.CLASSIFICATION_HOST
key = os.getenv("API_KEY")
secret = os.environ.get("SECRET_KEY")
debug = env("DEBUG")
```

## Import Handling

Both import styles are tracked:

```python
import os
import sys
from typing import List, Optional
from fastapi import FastAPI, Depends
```

Use `ast-index imports "file.py"` to see all imports with line numbers.

## Python-specific Reference Extraction

Ref extraction handles:
- `snake_case()` function calls
- `self._private_method()` calls
- `obj.method()` attribute calls
- `CamelCase` type references
- Excludes: Python keywords, builtins, import lines, definitions

## Performance

| Operation | Time |
|-----------|------|
| Rebuild (500 Python files) | ~500ms |
| Search class | ~1ms |
| Find usages | ~5ms |
| File outline | ~1ms |
| py.routes | ~2ms |
| py.endpoint-trace | ~3ms |
| py.setting-usage | ~2ms |
| py.model-impact | ~3ms |
| bundle | ~5ms |
