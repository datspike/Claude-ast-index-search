use criterion::{criterion_group, criterion_main, Criterion};

use ast_index::parsers::treesitter::{
    cpp::CPP_PARSER, csharp::CSHARP_PARSER, dart::DART_PARSER, go::GO_PARSER,
    java::JAVA_PARSER, kotlin::KOTLIN_PARSER, objc::OBJC_PARSER, proto::PROTO_PARSER,
    python::PYTHON_PARSER, ruby::RUBY_PARSER, rust_lang::RUST_PARSER, scala::SCALA_PARSER,
    swift::SWIFT_PARSER, typescript::TYPESCRIPT_PARSER, LanguageParser,
};

// ---------------------------------------------------------------------------
// Kotlin
// ---------------------------------------------------------------------------
const KOTLIN_SNIPPET: &str = r#"
package com.example.payments

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import javax.inject.Inject

sealed class PaymentState {
    object Idle : PaymentState()
    data class Loading(val orderId: String) : PaymentState()
    data class Success(val receipt: Receipt) : PaymentState()
    data class Error(val message: String, val code: Int) : PaymentState()
}

data class Receipt(
    val id: String,
    val amount: Double,
    val currency: String,
    val timestamp: Long,
)

interface PaymentRepository {
    suspend fun processPayment(orderId: String, amount: Double): Result<Receipt>
    suspend fun getPaymentHistory(userId: String): Flow<List<Receipt>>
    suspend fun refund(receiptId: String): Result<Unit>
}

class PaymentRepositoryImpl @Inject constructor(
    private val api: PaymentApi,
    private val cache: PaymentCache,
    private val analytics: AnalyticsTracker,
) : PaymentRepository {

    private val _state = MutableStateFlow<PaymentState>(PaymentState.Idle)
    val state: Flow<PaymentState> get() = _state

    override suspend fun processPayment(orderId: String, amount: Double): Result<Receipt> {
        _state.value = PaymentState.Loading(orderId)
        return try {
            val receipt = api.charge(orderId, amount)
            cache.save(receipt)
            analytics.track("payment_success", mapOf("order" to orderId))
            _state.value = PaymentState.Success(receipt)
            Result.success(receipt)
        } catch (e: Exception) {
            _state.value = PaymentState.Error(e.message ?: "Unknown", -1)
            Result.failure(e)
        }
    }

    override suspend fun getPaymentHistory(userId: String): Flow<List<Receipt>> {
        return cache.getHistory(userId)
    }

    override suspend fun refund(receiptId: String): Result<Unit> {
        return try {
            api.refund(receiptId)
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    companion object {
        const val MAX_RETRY = 3
        const val TIMEOUT_MS = 5000L
    }
}
"#;

// ---------------------------------------------------------------------------
// Java
// ---------------------------------------------------------------------------
const JAVA_SNIPPET: &str = r#"
package com.example.users;

import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import javax.validation.Valid;
import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/api/v1/users")
public class UserController {

    private final UserService userService;
    private final AuditLogger auditLogger;

    public UserController(UserService userService, AuditLogger auditLogger) {
        this.userService = userService;
        this.auditLogger = auditLogger;
    }

    @GetMapping
    public ResponseEntity<List<UserDto>> getAll(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        List<UserDto> users = userService.findAll(page, size);
        return ResponseEntity.ok(users);
    }

    @GetMapping("/{id}")
    public ResponseEntity<UserDto> getById(@PathVariable Long id) {
        Optional<UserDto> user = userService.findById(id);
        return user.map(ResponseEntity::ok)
                   .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping
    public ResponseEntity<UserDto> create(@Valid @RequestBody CreateUserRequest request) {
        UserDto created = userService.create(request);
        auditLogger.log("user_created", created.getId());
        return ResponseEntity.status(201).body(created);
    }

    @PutMapping("/{id}")
    public ResponseEntity<UserDto> update(
            @PathVariable Long id,
            @Valid @RequestBody UpdateUserRequest request) {
        UserDto updated = userService.update(id, request);
        return ResponseEntity.ok(updated);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable Long id) {
        userService.delete(id);
        auditLogger.log("user_deleted", id);
        return ResponseEntity.noContent().build();
    }
}

interface UserService {
    List<UserDto> findAll(int page, int size);
    Optional<UserDto> findById(Long id);
    UserDto create(CreateUserRequest request);
    UserDto update(Long id, UpdateUserRequest request);
    void delete(Long id);
}

class UserDto {
    private Long id;
    private String name;
    private String email;

    public Long getId() { return id; }
    public String getName() { return name; }
    public String getEmail() { return email; }
}
"#;

// ---------------------------------------------------------------------------
// Swift
// ---------------------------------------------------------------------------
const SWIFT_SNIPPET: &str = r#"
import Foundation
import Combine

protocol NetworkService {
    func fetch<T: Decodable>(url: URL) async throws -> T
    func upload(data: Data, to url: URL) async throws -> HTTPResponse
}

class APIClient: NetworkService {
    private let session: URLSession
    private let decoder: JSONDecoder
    private var cancellables = Set<AnyCancellable>()

    init(session: URLSession = .shared) {
        self.session = session
        self.decoder = JSONDecoder()
        self.decoder.dateDecodingStrategy = .iso8601
    }

    func fetch<T: Decodable>(url: URL) async throws -> T {
        let (data, response) = try await session.data(from: url)
        guard let httpResponse = response as? HTTPURLResponse,
              (200...299).contains(httpResponse.statusCode) else {
            throw NetworkError.invalidResponse
        }
        return try decoder.decode(T.self, from: data)
    }

    func upload(data: Data, to url: URL) async throws -> HTTPResponse {
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.httpBody = data
        let (responseData, _) = try await session.data(for: request)
        return try decoder.decode(HTTPResponse.self, from: responseData)
    }
}

extension APIClient {
    func fetchUsers() async throws -> [User] {
        let url = URL(string: "https://api.example.com/users")!
        return try await fetch(url: url)
    }
}

struct User: Codable, Identifiable {
    let id: UUID
    let name: String
    let email: String
    let createdAt: Date
}

enum NetworkError: Error {
    case invalidResponse
    case decodingError
    case unauthorized
}
"#;

// ---------------------------------------------------------------------------
// TypeScript
// ---------------------------------------------------------------------------
const TYPESCRIPT_SNIPPET: &str = r#"
import React, { useState, useEffect, useCallback } from 'react';

interface User {
    id: string;
    name: string;
    email: string;
    role: 'admin' | 'user' | 'guest';
}

interface UserListProps {
    initialPage?: number;
    pageSize?: number;
    onUserSelect?: (user: User) => void;
}

type FetchState<T> =
    | { status: 'idle' }
    | { status: 'loading' }
    | { status: 'success'; data: T }
    | { status: 'error'; error: Error };

class UserAPI {
    private baseUrl: string;

    constructor(baseUrl: string) {
        this.baseUrl = baseUrl;
    }

    async getUsers(page: number, size: number): Promise<User[]> {
        const res = await fetch(`${this.baseUrl}/users?page=${page}&size=${size}`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return res.json();
    }

    async deleteUser(id: string): Promise<void> {
        await fetch(`${this.baseUrl}/users/${id}`, { method: 'DELETE' });
    }
}

const UserList: React.FC<UserListProps> = ({ initialPage = 0, pageSize = 20, onUserSelect }) => {
    const [state, setState] = useState<FetchState<User[]>>({ status: 'idle' });
    const [page, setPage] = useState(initialPage);

    const fetchUsers = useCallback(async () => {
        setState({ status: 'loading' });
        try {
            const api = new UserAPI('/api/v1');
            const data = await api.getUsers(page, pageSize);
            setState({ status: 'success', data });
        } catch (error) {
            setState({ status: 'error', error: error as Error });
        }
    }, [page, pageSize]);

    useEffect(() => { fetchUsers(); }, [fetchUsers]);

    return null;
};

export default UserList;
export { UserAPI };
export type { User, UserListProps, FetchState };
"#;

// ---------------------------------------------------------------------------
// Python
// ---------------------------------------------------------------------------
const PYTHON_SNIPPET: &str = r#"
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from abc import ABC, abstractmethod
import logging

logger = logging.getLogger(__name__)

@dataclass
class Config:
    host: str = "localhost"
    port: int = 8080
    debug: bool = False
    max_connections: int = 100
    tags: Dict[str, str] = field(default_factory=dict)

class BaseHandler(ABC):
    def __init__(self, config: Config):
        self.config = config
        self._initialized = False

    @abstractmethod
    def handle(self, request: Dict[str, Any]) -> Dict[str, Any]:
        pass

    def validate(self, request: Dict[str, Any]) -> bool:
        return "action" in request and "payload" in request

class RequestHandler(BaseHandler):
    def __init__(self, config: Config, middleware: Optional[List] = None):
        super().__init__(config)
        self.middleware = middleware or []
        self._cache: Dict[str, Any] = {}

    def handle(self, request: Dict[str, Any]) -> Dict[str, Any]:
        if not self.validate(request):
            return {"error": "Invalid request"}
        for mw in self.middleware:
            request = mw.process(request)
        action = request["action"]
        if action in self._cache:
            return self._cache[action]
        result = self._process(request)
        self._cache[action] = result
        return result

    def _process(self, request: Dict[str, Any]) -> Dict[str, Any]:
        logger.info(f"Processing {request['action']}")
        return {"status": "ok", "data": request["payload"]}

@dataclass
class Response:
    status: int
    body: Dict[str, Any]
    headers: Dict[str, str] = field(default_factory=dict)

def create_app(config: Config) -> RequestHandler:
    return RequestHandler(config)
"#;

// ---------------------------------------------------------------------------
// Go
// ---------------------------------------------------------------------------
const GO_SNIPPET: &str = r#"
package server

import (
    "context"
    "encoding/json"
    "net/http"
    "sync"
    "time"
)

type Server struct {
    mu       sync.RWMutex
    handlers map[string]Handler
    config   *Config
    logger   Logger
}

type Config struct {
    Addr         string
    ReadTimeout  time.Duration
    WriteTimeout time.Duration
    MaxBodySize  int64
}

type Handler interface {
    ServeHTTP(w http.ResponseWriter, r *http.Request)
    Pattern() string
}

type Logger interface {
    Info(msg string, args ...interface{})
    Error(msg string, args ...interface{})
}

func NewServer(cfg *Config, logger Logger) *Server {
    return &Server{
        handlers: make(map[string]Handler),
        config:   cfg,
        logger:   logger,
    }
}

func (s *Server) Register(h Handler) {
    s.mu.Lock()
    defer s.mu.Unlock()
    s.handlers[h.Pattern()] = h
}

func (s *Server) Start(ctx context.Context) error {
    srv := &http.Server{
        Addr:         s.config.Addr,
        ReadTimeout:  s.config.ReadTimeout,
        WriteTimeout: s.config.WriteTimeout,
    }

    s.mu.RLock()
    mux := http.NewServeMux()
    for pattern, h := range s.handlers {
        mux.Handle(pattern, h)
    }
    s.mu.RUnlock()
    srv.Handler = mux

    go func() {
        <-ctx.Done()
        _ = srv.Shutdown(context.Background())
    }()

    s.logger.Info("starting server", "addr", s.config.Addr)
    return srv.ListenAndServe()
}

func respondJSON(w http.ResponseWriter, status int, data interface{}) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(status)
    _ = json.NewEncoder(w).Encode(data)
}
"#;

// ---------------------------------------------------------------------------
// Rust
// ---------------------------------------------------------------------------
const RUST_SNIPPET: &str = r#"
use std::collections::HashMap;
use std::sync::Arc;

pub trait Storage: Send + Sync {
    fn get(&self, key: &str) -> Option<Vec<u8>>;
    fn set(&self, key: &str, value: Vec<u8>) -> Result<(), StorageError>;
    fn delete(&self, key: &str) -> Result<(), StorageError>;
}

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("key not found: {0}")]
    NotFound(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub struct InMemoryStorage {
    data: parking_lot::RwLock<HashMap<String, Vec<u8>>>,
}

impl InMemoryStorage {
    pub fn new() -> Self {
        Self {
            data: parking_lot::RwLock::new(HashMap::new()),
        }
    }
}

impl Storage for InMemoryStorage {
    fn get(&self, key: &str) -> Option<Vec<u8>> {
        self.data.read().get(key).cloned()
    }

    fn set(&self, key: &str, value: Vec<u8>) -> Result<(), StorageError> {
        self.data.write().insert(key.to_string(), value);
        Ok(())
    }

    fn delete(&self, key: &str) -> Result<(), StorageError> {
        self.data
            .write()
            .remove(key)
            .map(|_| ())
            .ok_or_else(|| StorageError::NotFound(key.to_string()))
    }
}

pub enum CachePolicy {
    NoCache,
    Ttl(std::time::Duration),
    Forever,
}

pub struct CachedStorage<S: Storage> {
    inner: Arc<S>,
    policy: CachePolicy,
}

impl<S: Storage> CachedStorage<S> {
    pub fn new(inner: Arc<S>, policy: CachePolicy) -> Self {
        Self { inner, policy }
    }
}
"#;

// ---------------------------------------------------------------------------
// C++
// ---------------------------------------------------------------------------
const CPP_SNIPPET: &str = r#"
#include <memory>
#include <string>
#include <vector>
#include <unordered_map>

namespace engine {
namespace rendering {

class Texture {
public:
    Texture(int width, int height, int channels);
    ~Texture();

    int width() const { return width_; }
    int height() const { return height_; }
    void bind(unsigned int unit) const;

private:
    int width_;
    int height_;
    int channels_;
    unsigned int handle_;
};

class Material {
public:
    Material(const std::string& name);
    void setTexture(const std::string& slot, std::shared_ptr<Texture> tex);
    void setUniform(const std::string& name, float value);
    void apply() const;

private:
    std::string name_;
    std::unordered_map<std::string, std::shared_ptr<Texture>> textures_;
    std::unordered_map<std::string, float> uniforms_;
};

template<typename T>
class ResourceCache {
public:
    std::shared_ptr<T> get(const std::string& key) const;
    void put(const std::string& key, std::shared_ptr<T> resource);
    void evict(const std::string& key);
    size_t size() const { return cache_.size(); }

private:
    std::unordered_map<std::string, std::shared_ptr<T>> cache_;
};

class Renderer {
public:
    Renderer();
    virtual ~Renderer() = default;

    virtual void beginFrame();
    virtual void endFrame();
    virtual void draw(const Material& material, const std::vector<float>& vertices);

protected:
    int frameCount_;
    ResourceCache<Texture> textureCache_;
};

} // namespace rendering
} // namespace engine
"#;

// ---------------------------------------------------------------------------
// C#
// ---------------------------------------------------------------------------
const CSHARP_SNIPPET: &str = r#"
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;

namespace App.Controllers
{
    public interface IProductService
    {
        Task<IEnumerable<ProductDto>> GetAllAsync(int page, int size);
        Task<ProductDto?> GetByIdAsync(Guid id);
        Task<ProductDto> CreateAsync(CreateProductRequest request);
        Task DeleteAsync(Guid id);
    }

    public record ProductDto(Guid Id, string Name, decimal Price, string Category);

    public record CreateProductRequest(string Name, decimal Price, string Category);

    [ApiController]
    [Route("api/[controller]")]
    public class ProductsController : ControllerBase
    {
        private readonly IProductService _service;
        private readonly ILogger<ProductsController> _logger;

        public ProductsController(IProductService service, ILogger<ProductsController> logger)
        {
            _service = service;
            _logger = logger;
        }

        [HttpGet]
        public async Task<ActionResult<IEnumerable<ProductDto>>> GetAll(
            [FromQuery] int page = 0,
            [FromQuery] int size = 20)
        {
            var products = await _service.GetAllAsync(page, size);
            return Ok(products);
        }

        [HttpGet("{id:guid}")]
        public async Task<ActionResult<ProductDto>> GetById(Guid id)
        {
            var product = await _service.GetByIdAsync(id);
            if (product is null) return NotFound();
            return Ok(product);
        }

        [HttpPost]
        public async Task<ActionResult<ProductDto>> Create([FromBody] CreateProductRequest request)
        {
            var product = await _service.CreateAsync(request);
            _logger.LogInformation("Created product {Id}", product.Id);
            return CreatedAtAction(nameof(GetById), new { id = product.Id }, product);
        }

        [HttpDelete("{id:guid}")]
        public async Task<IActionResult> Delete(Guid id)
        {
            await _service.DeleteAsync(id);
            return NoContent();
        }
    }
}
"#;

// ---------------------------------------------------------------------------
// Ruby
// ---------------------------------------------------------------------------
const RUBY_SNIPPET: &str = r#"
module Authentication
  class TokenService
    attr_reader :secret, :expiry

    def initialize(secret:, expiry: 3600)
      @secret = secret
      @expiry = expiry
    end

    def generate(user)
      payload = {
        user_id: user.id,
        email: user.email,
        exp: Time.now.to_i + expiry
      }
      encode(payload)
    end

    def verify(token)
      payload = decode(token)
      return nil if payload.nil? || expired?(payload)
      payload
    end

    private

    def encode(payload)
      # JWT encode
      payload.to_json
    end

    def decode(token)
      JSON.parse(token, symbolize_names: true)
    rescue JSON::ParserError
      nil
    end

    def expired?(payload)
      payload[:exp] < Time.now.to_i
    end
  end

  class Middleware
    def initialize(app, token_service:)
      @app = app
      @token_service = token_service
    end

    def call(env)
      token = extract_token(env)
      if token
        payload = @token_service.verify(token)
        env['auth.user'] = payload if payload
      end
      @app.call(env)
    end

    private

    def extract_token(env)
      header = env['HTTP_AUTHORIZATION']
      return nil unless header&.start_with?('Bearer ')
      header.sub('Bearer ', '')
    end
  end
end

class User
  attr_accessor :id, :email, :name, :role

  def initialize(id:, email:, name:, role: :user)
    @id = id
    @email = email
    @name = name
    @role = role
  end

  def admin?
    role == :admin
  end
end
"#;

// ---------------------------------------------------------------------------
// Dart
// ---------------------------------------------------------------------------
const DART_SNIPPET: &str = r#"
import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';

abstract class AppEvent {}

class LoadDataEvent extends AppEvent {
  final String query;
  LoadDataEvent(this.query);
}

class RefreshEvent extends AppEvent {}

abstract class AppState {}

class InitialState extends AppState {}
class LoadingState extends AppState {}

class LoadedState extends AppState {
  final List<Item> items;
  LoadedState(this.items);
}

class ErrorState extends AppState {
  final String message;
  ErrorState(this.message);
}

class Item {
  final String id;
  final String title;
  final double price;
  final bool available;

  const Item({
    required this.id,
    required this.title,
    required this.price,
    this.available = true,
  });
}

mixin LoggerMixin {
  void log(String message) {
    debugPrint('[${runtimeType}] $message');
  }
}

extension StringExtensions on String {
  String capitalize() {
    if (isEmpty) return this;
    return '${this[0].toUpperCase()}${substring(1)}';
  }

  bool get isValidEmail {
    return RegExp(r'^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$').hasMatch(this);
  }
}

class AppBloc extends Bloc<AppEvent, AppState> with LoggerMixin {
  final Repository repository;

  AppBloc({required this.repository}) : super(InitialState()) {
    on<LoadDataEvent>(_onLoad);
    on<RefreshEvent>(_onRefresh);
  }

  Future<void> _onLoad(LoadDataEvent event, Emitter<AppState> emit) async {
    emit(LoadingState());
    try {
      final items = await repository.search(event.query);
      emit(LoadedState(items));
    } catch (e) {
      emit(ErrorState(e.toString()));
    }
  }

  Future<void> _onRefresh(RefreshEvent event, Emitter<AppState> emit) async {
    final items = await repository.getAll();
    emit(LoadedState(items));
  }
}

abstract class Repository {
  Future<List<Item>> getAll();
  Future<List<Item>> search(String query);
}
"#;

// ---------------------------------------------------------------------------
// Scala
// ---------------------------------------------------------------------------
const SCALA_SNIPPET: &str = r#"
package com.example.catalog

import scala.concurrent.Future
import scala.concurrent.ExecutionContext.Implicits.global

sealed trait CatalogError
case class NotFound(id: String) extends CatalogError
case class ValidationError(field: String, message: String) extends CatalogError

case class Product(
  id: String,
  name: String,
  price: BigDecimal,
  category: String,
  tags: List[String] = Nil
)

trait CatalogRepository {
  def findById(id: String): Future[Option[Product]]
  def findByCategory(category: String): Future[List[Product]]
  def save(product: Product): Future[Either[CatalogError, Product]]
  def delete(id: String): Future[Either[CatalogError, Unit]]
}

object CatalogRepository {
  def apply(config: DatabaseConfig): CatalogRepository = new CatalogRepositoryImpl(config)
}

case class DatabaseConfig(url: String, maxPoolSize: Int = 10)

class CatalogRepositoryImpl(config: DatabaseConfig) extends CatalogRepository {
  private var store: Map[String, Product] = Map.empty

  override def findById(id: String): Future[Option[Product]] =
    Future.successful(store.get(id))

  override def findByCategory(category: String): Future[List[Product]] =
    Future.successful(store.values.filter(_.category == category).toList)

  override def save(product: Product): Future[Either[CatalogError, Product]] = Future {
    if (product.name.isEmpty)
      Left(ValidationError("name", "Name cannot be empty"))
    else {
      store = store + (product.id -> product)
      Right(product)
    }
  }

  override def delete(id: String): Future[Either[CatalogError, Unit]] = Future {
    if (store.contains(id)) {
      store = store - id
      Right(())
    } else Left(NotFound(id))
  }
}

trait CatalogService {
  def getProduct(id: String): Future[Either[CatalogError, Product]]
  def listByCategory(category: String): Future[List[Product]]
}
"#;

// ---------------------------------------------------------------------------
// Proto
// ---------------------------------------------------------------------------
const PROTO_SNIPPET: &str = r#"
syntax = "proto3";

package api.v1;

option java_package = "com.example.api.v1";
option go_package = "github.com/example/api/v1;apiv1";

import "google/protobuf/timestamp.proto";
import "google/protobuf/empty.proto";

enum OrderStatus {
  ORDER_STATUS_UNSPECIFIED = 0;
  ORDER_STATUS_PENDING = 1;
  ORDER_STATUS_CONFIRMED = 2;
  ORDER_STATUS_SHIPPED = 3;
  ORDER_STATUS_DELIVERED = 4;
  ORDER_STATUS_CANCELLED = 5;
}

message Address {
  string street = 1;
  string city = 2;
  string state = 3;
  string zip_code = 4;
  string country = 5;
}

message OrderItem {
  string product_id = 1;
  int32 quantity = 2;
  double unit_price = 3;
  string name = 4;
}

message Order {
  string id = 1;
  string customer_id = 2;
  repeated OrderItem items = 3;
  OrderStatus status = 4;
  Address shipping_address = 5;
  double total_amount = 6;
  google.protobuf.Timestamp created_at = 7;
  google.protobuf.Timestamp updated_at = 8;
  map<string, string> metadata = 9;
}

message CreateOrderRequest {
  string customer_id = 1;
  repeated OrderItem items = 2;
  Address shipping_address = 3;
}

message CreateOrderResponse {
  Order order = 1;
}

message GetOrderRequest {
  string id = 1;
}

message ListOrdersRequest {
  string customer_id = 1;
  int32 page_size = 2;
  string page_token = 3;
  OrderStatus status_filter = 4;
}

message ListOrdersResponse {
  repeated Order orders = 1;
  string next_page_token = 2;
  int32 total_count = 3;
}

service OrderService {
  rpc CreateOrder(CreateOrderRequest) returns (CreateOrderResponse);
  rpc GetOrder(GetOrderRequest) returns (Order);
  rpc ListOrders(ListOrdersRequest) returns (ListOrdersResponse);
  rpc CancelOrder(GetOrderRequest) returns (google.protobuf.Empty);
}
"#;

// ---------------------------------------------------------------------------
// Objective-C
// ---------------------------------------------------------------------------
const OBJC_SNIPPET: &str = r#"
#import <Foundation/Foundation.h>

@protocol NetworkClientDelegate <NSObject>
- (void)client:(id)client didReceiveData:(NSData *)data;
- (void)client:(id)client didFailWithError:(NSError *)error;
@optional
- (void)clientDidFinishLoading:(id)client;
@end

@interface NetworkClient : NSObject

@property (nonatomic, weak) id<NetworkClientDelegate> delegate;
@property (nonatomic, copy, readonly) NSString *baseURL;
@property (nonatomic, assign) NSTimeInterval timeout;

- (instancetype)initWithBaseURL:(NSString *)baseURL;
- (void)GET:(NSString *)path parameters:(NSDictionary *)params completion:(void (^)(id, NSError *))completion;
- (void)POST:(NSString *)path body:(NSDictionary *)body completion:(void (^)(id, NSError *))completion;
- (void)cancelAllRequests;

@end

@implementation NetworkClient

- (instancetype)initWithBaseURL:(NSString *)baseURL {
    self = [super init];
    if (self) {
        _baseURL = [baseURL copy];
        _timeout = 30.0;
    }
    return self;
}

- (void)GET:(NSString *)path parameters:(NSDictionary *)params completion:(void (^)(id, NSError *))completion {
    NSString *url = [NSString stringWithFormat:@"%@/%@", self.baseURL, path];
    NSURLRequest *request = [NSURLRequest requestWithURL:[NSURL URLWithString:url]];
    [self performRequest:request completion:completion];
}

- (void)POST:(NSString *)path body:(NSDictionary *)body completion:(void (^)(id, NSError *))completion {
    NSString *url = [NSString stringWithFormat:@"%@/%@", self.baseURL, path];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:url]];
    request.HTTPMethod = @"POST";
    request.HTTPBody = [NSJSONSerialization dataWithJSONObject:body options:0 error:nil];
    [self performRequest:request completion:completion];
}

- (void)performRequest:(NSURLRequest *)request completion:(void (^)(id, NSError *))completion {
    NSURLSessionDataTask *task = [[NSURLSession sharedSession] dataTaskWithRequest:request
        completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
            if (error) {
                completion(nil, error);
                return;
            }
            id json = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
            completion(json, nil);
        }];
    [task resume];
}

- (void)cancelAllRequests {
    [[NSURLSession sharedSession] invalidateAndCancel];
}

@end
"#;

// ---------------------------------------------------------------------------
// Large Kotlin (~300 lines)
// ---------------------------------------------------------------------------
const LARGE_KOTLIN_SNIPPET: &str = r#"
package com.example.feature.checkout

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.map
import javax.inject.Inject

sealed class CheckoutEvent {
    data class AddItem(val productId: String, val quantity: Int) : CheckoutEvent()
    data class RemoveItem(val productId: String) : CheckoutEvent()
    data class UpdateQuantity(val productId: String, val quantity: Int) : CheckoutEvent()
    data class ApplyPromo(val code: String) : CheckoutEvent()
    object ClearCart : CheckoutEvent()
    data class SetShipping(val address: ShippingAddress) : CheckoutEvent()
    data class SetPayment(val method: PaymentMethod) : CheckoutEvent()
    object PlaceOrder : CheckoutEvent()
}

sealed class CheckoutState {
    object Empty : CheckoutState()
    data class Active(
        val items: List<CartItem>,
        val subtotal: Double,
        val discount: Double,
        val shipping: Double,
        val total: Double,
        val promoCode: String? = null,
        val shippingAddress: ShippingAddress? = null,
        val paymentMethod: PaymentMethod? = null,
    ) : CheckoutState()
    data class Processing(val orderId: String) : CheckoutState()
    data class Completed(val orderId: String, val receipt: OrderReceipt) : CheckoutState()
    data class Failed(val error: String) : CheckoutState()
}

data class CartItem(
    val productId: String,
    val name: String,
    val price: Double,
    val quantity: Int,
    val imageUrl: String,
) {
    val lineTotal: Double get() = price * quantity
}

data class ShippingAddress(
    val name: String,
    val street: String,
    val city: String,
    val state: String,
    val zipCode: String,
    val country: String,
)

sealed class PaymentMethod {
    data class CreditCard(val last4: String, val brand: String, val token: String) : PaymentMethod()
    data class PayPal(val email: String) : PaymentMethod()
    object ApplePay : PaymentMethod()
    object GooglePay : PaymentMethod()
}

data class OrderReceipt(
    val orderId: String,
    val items: List<CartItem>,
    val total: Double,
    val timestamp: Long,
)

interface CheckoutRepository {
    suspend fun calculateShipping(address: ShippingAddress, items: List<CartItem>): Double
    suspend fun validatePromo(code: String): PromoResult
    suspend fun placeOrder(state: CheckoutState.Active): Result<OrderReceipt>
    fun getCartItems(): Flow<List<CartItem>>
}

sealed class PromoResult {
    data class Valid(val discount: Double, val description: String) : PromoResult()
    data class Invalid(val reason: String) : PromoResult()
    data class Expired(val expiredAt: Long) : PromoResult()
}

class CheckoutViewModel @Inject constructor(
    private val repository: CheckoutRepository,
    private val analytics: AnalyticsTracker,
    private val logger: AppLogger,
) {
    private val _state = MutableStateFlow<CheckoutState>(CheckoutState.Empty)
    val state: StateFlow<CheckoutState> = _state.asStateFlow()

    val itemCount: Flow<Int> = _state.map { st ->
        when (st) {
            is CheckoutState.Active -> st.items.sumOf { it.quantity }
            else -> 0
        }
    }

    suspend fun onEvent(event: CheckoutEvent) {
        when (event) {
            is CheckoutEvent.AddItem -> addItem(event.productId, event.quantity)
            is CheckoutEvent.RemoveItem -> removeItem(event.productId)
            is CheckoutEvent.UpdateQuantity -> updateQuantity(event.productId, event.quantity)
            is CheckoutEvent.ApplyPromo -> applyPromo(event.code)
            is CheckoutEvent.ClearCart -> clearCart()
            is CheckoutEvent.SetShipping -> setShipping(event.address)
            is CheckoutEvent.SetPayment -> setPayment(event.method)
            is CheckoutEvent.PlaceOrder -> placeOrder()
        }
    }

    private suspend fun addItem(productId: String, quantity: Int) {
        val current = _state.value
        logger.debug("Adding item $productId x$quantity")
        analytics.track("cart_add", mapOf("product" to productId, "qty" to quantity.toString()))
        when (current) {
            is CheckoutState.Empty -> {
                // Load from repository
            }
            is CheckoutState.Active -> {
                val existing = current.items.find { it.productId == productId }
                val newItems = if (existing != null) {
                    current.items.map {
                        if (it.productId == productId) it.copy(quantity = it.quantity + quantity)
                        else it
                    }
                } else {
                    current.items + CartItem(productId, "Product", 0.0, quantity, "")
                }
                _state.value = recalculate(current.copy(items = newItems))
            }
            else -> { /* ignore */ }
        }
    }

    private fun removeItem(productId: String) {
        val current = _state.value as? CheckoutState.Active ?: return
        val newItems = current.items.filter { it.productId != productId }
        if (newItems.isEmpty()) {
            _state.value = CheckoutState.Empty
        } else {
            _state.value = recalculate(current.copy(items = newItems))
        }
    }

    private fun updateQuantity(productId: String, quantity: Int) {
        val current = _state.value as? CheckoutState.Active ?: return
        if (quantity <= 0) {
            removeItem(productId)
            return
        }
        val newItems = current.items.map {
            if (it.productId == productId) it.copy(quantity = quantity) else it
        }
        _state.value = recalculate(current.copy(items = newItems))
    }

    private suspend fun applyPromo(code: String) {
        val current = _state.value as? CheckoutState.Active ?: return
        when (val result = repository.validatePromo(code)) {
            is PromoResult.Valid -> {
                _state.value = recalculate(current.copy(promoCode = code, discount = result.discount))
                analytics.track("promo_applied", mapOf("code" to code))
            }
            is PromoResult.Invalid -> {
                logger.warn("Invalid promo: ${result.reason}")
            }
            is PromoResult.Expired -> {
                logger.warn("Promo expired at ${result.expiredAt}")
            }
        }
    }

    private fun clearCart() {
        _state.value = CheckoutState.Empty
        analytics.track("cart_cleared", emptyMap())
    }

    private suspend fun setShipping(address: ShippingAddress) {
        val current = _state.value as? CheckoutState.Active ?: return
        val shippingCost = repository.calculateShipping(address, current.items)
        _state.value = recalculate(current.copy(shippingAddress = address, shipping = shippingCost))
    }

    private fun setPayment(method: PaymentMethod) {
        val current = _state.value as? CheckoutState.Active ?: return
        _state.value = current.copy(paymentMethod = method)
    }

    private suspend fun placeOrder() {
        val current = _state.value as? CheckoutState.Active ?: return
        _state.value = CheckoutState.Processing("pending")
        val result = repository.placeOrder(current)
        result.fold(
            onSuccess = { receipt ->
                _state.value = CheckoutState.Completed(receipt.orderId, receipt)
                analytics.track("order_placed", mapOf("order" to receipt.orderId))
            },
            onFailure = { error ->
                _state.value = CheckoutState.Failed(error.message ?: "Order failed")
                logger.error("Order failed", error)
            }
        )
    }

    private fun recalculate(state: CheckoutState.Active): CheckoutState.Active {
        val subtotal = state.items.sumOf { it.lineTotal }
        val total = subtotal - state.discount + state.shipping
        return state.copy(subtotal = subtotal, total = total)
    }

    companion object {
        const val MAX_ITEMS = 99
        const val MAX_QUANTITY_PER_ITEM = 10
        const val FREE_SHIPPING_THRESHOLD = 50.0
    }
}

interface AnalyticsTracker {
    fun track(event: String, params: Map<String, String>)
}

interface AppLogger {
    fun debug(msg: String)
    fun warn(msg: String)
    fun error(msg: String, throwable: Throwable? = null)
}
"#;

// ---------------------------------------------------------------------------
// Large Java (~300 lines)
// ---------------------------------------------------------------------------
const LARGE_JAVA_SNIPPET: &str = r#"
package com.example.inventory;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import javax.validation.Valid;
import javax.validation.constraints.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

enum StockStatus {
    IN_STOCK,
    LOW_STOCK,
    OUT_OF_STOCK,
    DISCONTINUED
}

class InventoryItem {
    private String sku;
    private String name;
    private String category;
    private int quantity;
    private int reservedQuantity;
    private double unitPrice;
    private StockStatus status;
    private Instant lastUpdated;

    public InventoryItem(String sku, String name, String category, int quantity, double unitPrice) {
        this.sku = sku;
        this.name = name;
        this.category = category;
        this.quantity = quantity;
        this.unitPrice = unitPrice;
        this.reservedQuantity = 0;
        this.status = quantity > 10 ? StockStatus.IN_STOCK : StockStatus.LOW_STOCK;
        this.lastUpdated = Instant.now();
    }

    public String getSku() { return sku; }
    public String getName() { return name; }
    public String getCategory() { return category; }
    public int getQuantity() { return quantity; }
    public int getReservedQuantity() { return reservedQuantity; }
    public int getAvailableQuantity() { return quantity - reservedQuantity; }
    public double getUnitPrice() { return unitPrice; }
    public StockStatus getStatus() { return status; }
    public Instant getLastUpdated() { return lastUpdated; }

    public void setQuantity(int quantity) {
        this.quantity = quantity;
        this.lastUpdated = Instant.now();
        updateStatus();
    }

    public void setReservedQuantity(int reserved) {
        this.reservedQuantity = reserved;
        this.lastUpdated = Instant.now();
    }

    private void updateStatus() {
        if (quantity == 0) status = StockStatus.OUT_OF_STOCK;
        else if (quantity <= 10) status = StockStatus.LOW_STOCK;
        else status = StockStatus.IN_STOCK;
    }
}

interface InventoryRepository {
    Optional<InventoryItem> findBySku(String sku);
    List<InventoryItem> findByCategory(String category);
    List<InventoryItem> findByStatus(StockStatus status);
    List<InventoryItem> findAll();
    InventoryItem save(InventoryItem item);
    void deleteBySku(String sku);
}

class InMemoryInventoryRepository implements InventoryRepository {
    private final Map<String, InventoryItem> store = new ConcurrentHashMap<>();

    @Override
    public Optional<InventoryItem> findBySku(String sku) {
        return Optional.ofNullable(store.get(sku));
    }

    @Override
    public List<InventoryItem> findByCategory(String category) {
        return store.values().stream()
            .filter(item -> item.getCategory().equals(category))
            .collect(Collectors.toList());
    }

    @Override
    public List<InventoryItem> findByStatus(StockStatus status) {
        return store.values().stream()
            .filter(item -> item.getStatus() == status)
            .collect(Collectors.toList());
    }

    @Override
    public List<InventoryItem> findAll() {
        return new ArrayList<>(store.values());
    }

    @Override
    public InventoryItem save(InventoryItem item) {
        store.put(item.getSku(), item);
        return item;
    }

    @Override
    public void deleteBySku(String sku) {
        store.remove(sku);
    }
}

class ReservationRequest {
    @NotBlank private String sku;
    @Min(1) @Max(1000) private int quantity;
    @NotBlank private String orderId;

    public String getSku() { return sku; }
    public int getQuantity() { return quantity; }
    public String getOrderId() { return orderId; }
}

class ReservationResult {
    private boolean success;
    private String message;
    private String reservationId;

    public ReservationResult(boolean success, String message, String reservationId) {
        this.success = success;
        this.message = message;
        this.reservationId = reservationId;
    }

    public boolean isSuccess() { return success; }
    public String getMessage() { return message; }
    public String getReservationId() { return reservationId; }
}

@Service
class InventoryService {
    private final InventoryRepository repository;
    private final Map<String, List<String>> reservations = new ConcurrentHashMap<>();

    public InventoryService(InventoryRepository repository) {
        this.repository = repository;
    }

    @Transactional
    public ReservationResult reserve(ReservationRequest request) {
        Optional<InventoryItem> itemOpt = repository.findBySku(request.getSku());
        if (itemOpt.isEmpty()) {
            return new ReservationResult(false, "SKU not found", null);
        }

        InventoryItem item = itemOpt.get();
        if (item.getAvailableQuantity() < request.getQuantity()) {
            return new ReservationResult(false, "Insufficient stock", null);
        }

        item.setReservedQuantity(item.getReservedQuantity() + request.getQuantity());
        repository.save(item);

        String reservationId = UUID.randomUUID().toString();
        reservations.computeIfAbsent(request.getOrderId(), k -> new ArrayList<>()).add(reservationId);

        return new ReservationResult(true, "Reserved", reservationId);
    }

    public List<InventoryItem> getLowStock() {
        return repository.findByStatus(StockStatus.LOW_STOCK);
    }

    public Map<String, Long> getCategoryCounts() {
        return repository.findAll().stream()
            .collect(Collectors.groupingBy(InventoryItem::getCategory, Collectors.counting()));
    }
}

@RestController
@RequestMapping("/api/v1/inventory")
class InventoryController {
    private final InventoryService service;

    public InventoryController(InventoryService service) {
        this.service = service;
    }

    @PostMapping("/reserve")
    public ResponseEntity<ReservationResult> reserve(@Valid @RequestBody ReservationRequest request) {
        ReservationResult result = service.reserve(request);
        if (result.isSuccess()) {
            return ResponseEntity.ok(result);
        }
        return ResponseEntity.badRequest().body(result);
    }

    @GetMapping("/low-stock")
    public ResponseEntity<List<InventoryItem>> getLowStock() {
        return ResponseEntity.ok(service.getLowStock());
    }

    @GetMapping("/category-counts")
    public ResponseEntity<Map<String, Long>> getCategoryCounts() {
        return ResponseEntity.ok(service.getCategoryCounts());
    }
}
"#;

// ---------------------------------------------------------------------------
// Benchmark group
// ---------------------------------------------------------------------------
fn bench_treesitter_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("treesitter_parsing");

    macro_rules! bench_parser {
        ($name:expr, $parser:expr, $snippet:expr) => {
            group.bench_function($name, |b| {
                b.iter(|| {
                    let _ = $parser.parse_symbols(criterion::black_box($snippet));
                });
            });
        };
    }

    bench_parser!("kotlin", KOTLIN_PARSER, KOTLIN_SNIPPET);
    bench_parser!("java", JAVA_PARSER, JAVA_SNIPPET);
    bench_parser!("swift", SWIFT_PARSER, SWIFT_SNIPPET);
    bench_parser!("typescript", TYPESCRIPT_PARSER, TYPESCRIPT_SNIPPET);
    bench_parser!("python", PYTHON_PARSER, PYTHON_SNIPPET);
    bench_parser!("go", GO_PARSER, GO_SNIPPET);
    bench_parser!("rust", RUST_PARSER, RUST_SNIPPET);
    bench_parser!("cpp", CPP_PARSER, CPP_SNIPPET);
    bench_parser!("csharp", CSHARP_PARSER, CSHARP_SNIPPET);
    bench_parser!("ruby", RUBY_PARSER, RUBY_SNIPPET);
    bench_parser!("dart", DART_PARSER, DART_SNIPPET);
    bench_parser!("scala", SCALA_PARSER, SCALA_SNIPPET);
    bench_parser!("proto", PROTO_PARSER, PROTO_SNIPPET);
    bench_parser!("objc", OBJC_PARSER, OBJC_SNIPPET);

    group.finish();
}

fn bench_large_files(c: &mut Criterion) {
    let mut group = c.benchmark_group("large_file_parsing");

    group.bench_function("kotlin_300_lines", |b| {
        b.iter(|| {
            let _ = KOTLIN_PARSER.parse_symbols(criterion::black_box(LARGE_KOTLIN_SNIPPET));
        });
    });

    group.bench_function("java_300_lines", |b| {
        b.iter(|| {
            let _ = JAVA_PARSER.parse_symbols(criterion::black_box(LARGE_JAVA_SNIPPET));
        });
    });

    group.finish();
}

criterion_group!(benches, bench_treesitter_parsing, bench_large_files);
criterion_main!(benches);
