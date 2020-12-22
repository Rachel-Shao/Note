# HTTP Server

理解 HTTP 构建的网络应用只要关注两个端：**客户端（clinet）**和**服务端（server）**，两个端的交互来自 clinet 的 request，以及 server 端的 response。所谓的 http 服务器，主要在于如何接受 clinet 的 request，并向 client 返回 response。

接收request的过程中，最重要的莫过于路由（router），即实现一个Multiplexer(多路复用器)。Go中既可以使用内置的mutilplexer --- DefautServeMux，也可以自定义。

Multiplexer 路由的目的就是为了找到处理器函数（handler），后者将对request进行处理，同时构建response。

**[ Clinet -> Requests ->  Multiplexer(router) -> handler  -> Response -> Clinet ]**



## 简单实例

一个简单的http服务器实现：在本机的 9090 端口开启一个 web 服务，当访问 http://localhost:9090/  时，网页会显示 hello world

```go
// mini web server
package main

import (
  "fmt"
  "log"
  "net/http"
)

func IndexHandler(w http.ResponseWriter, r *http.Request) {
  fmt.Fprintln(w, "<h1>hello world</h1>")
}

func main()  {
  http.HandleFunc("/", IndexHandler)
  // 第一个参数是监听的端口。第二个参数是支持一个自定义的 multiplexer，如果为 nil 则用默认的
  log.Fatal(http.ListenAndServe(":9090", nil))
}
```

其中一些函数的分析：

- **Handler 接口**

```go
// 它要求实现 ServeHTTP 方法
type Handler interface {
        ServeHTTP(ResponseWriter, *Request)
}
```

Handler 用来响应 HTTP 请求，ServeHTTP 方法会将回复的 header 以及 data 都写到 `ResponseWriter` 中然后返回。

但是，一旦完成了 ServeHTTP 调用，我们就不能再读取 `Request.Body`，也不能再使用 `ResponseWrite`。而我们就可能会遇到一写入`ResponseWrite`就立刻无法读取`Request.Body`的情况，所以我们应该先读取`Request.Body`再回复。就有了`HandleFunc`：

- **HandleFunc 方法** 

```go
// http.HandleFunc
func HandleFunc(pattern string, handler func(ResponseWriter, *Request))
```

HandleFunc 将 handle function 注册给一个 pattern，就像我们在上面的程序中将 `IndexHandler` 注册给了根目录 `"/"`。

以后访问根目录就会使用对应 handler 进行处理。具体的如何匹配 pattern 就需要了解 ServeMux 了。

- **ServeMux**

Golang中的Multiplexer基于`ServeMux`结构，同时也实现了`Handler`接口。

ServeMux 是一个 HTTP 请求的多路复用器。它会将请求的 URL 与已注册的所有 pattern 进行匹配，然后调用最相似的一个。

ServeMux 的实现很简单，主要是基于一个字典进行查询。

```go
type ServeMux struct {
    mu    sync.RWMutex
    m     map[string]muxEntry
    hosts bool 
}

type muxEntry struct {
    explicit bool
    h        Handler
    pattern  string
}
```



## 源码分析

以openyert源码为例，浏览下http server的创建过程。

yurtHubServer对象有`Run()`方法，整体如下：

```go
func (s *yurtHubServer) Run() {
  // 1.注册handler 
  s.registerHandler()

  // 2.创建server
   server := &http.Server{
     Addr:    fmt.Sprintf("%s:%d", s.cfg.YurtHubHost, s.cfg.YurtHubPort),  // 监听的tcp地址
     Handler: s.mux,  // 注册的路由处理器方法
   }

  // 3.启动server
   err := server.ListenAndServe()
   ...
}
```

包括以下步骤：

1. 注册路由s.registerHandler()

   ~~~go
   func (s *yurtHubServer) registerHandler() {
      // register handler for health check
      s.mux.HandleFunc("/v1/healthz", s.healthz).Methods("GET")
   
      // register handler for profile
      profile.Install(s.mux)
   
      // attention: "/" route must be put at the end of registerHandler
      // register handlers for proxy to kube-apiserver
      s.mux.PathPrefix("/").Handler(s.proxyHandler)
   }
   ~~~

   这里有一个`HandleFunc()`函数，用于给健康监测注册路由，看看这个函数：

   ```go
   // HandleFunc registers a new route with a matcher for the URL path.
   // See Route.Path() and Route.HandlerFunc().
   func (r *Router) HandleFunc(path string, f func(http.ResponseWriter,
      *http.Request)) *Route {
      // 反正就是把path和f绑定
      return r.NewRoute().Path(path).HandlerFunc(f)
   }
   
   type Route struct {
       handler     http.Handler
       buildOnly   bool
       name        string
       err         error
       namedRoutes map[string]*Route
       routeConf
   }
   
   // NewRoute registers an empty route.
   func (r *Router) NewRoute() *Route {
   	// initialize a route with a copy of the parent router's configuration
   	route := &Route{routeConf: copyRouteConf(r.routeConf), namedRoutes: r.namedRoutes}
   	r.routes = append(r.routes, route)
   	return route
   }
   
   // HandlerFunc sets a handler function for the route.
   func (r *Route) HandlerFunc(f func(http.ResponseWriter, *http.Request)) *Route {
   	return r.Handler(http.HandlerFunc(f))
     // 此处的Handler()函数就是将r.handler参数设置成http.HandlerFunc(f)
   }
   
   
   // The HandlerFunc type is an adapter to allow the use of
   // ordinary functions as HTTP handlers. If f is a function
   // with the appropriate signature, HandlerFunc(f) is a
   // Handler that calls f.
   type HandlerFunc func(ResponseWriter, *Request)
   
   // ServeHTTP calls f(w, r).
   func (f HandlerFunc) ServeHTTP(w ResponseWriter, r *Request) {
   	f(w, r)
   }
   ```

   这里最后的`HandlerFunc` 是用 type 定义的函数，而函数的类型就是最开始传入的类型`func(ResponseWriter, *Request)`
    ServeHTTP是HandlerFunc的一个方法。并且HandlerFunc实现了 Handler接口：

   ```go
   type Handler interface {
       ServeHTTP(ResponseWriter, *Request)
   }
   ```

   上文中`return r.Handler(http.HandlerFunc(f))`里的`http.HandlerFunc(f)`就是把传入的f强制转换成`HandlerFunc`类型，这样f就可以实现Handler接口。[这样，之后的程序中依据`path`会调用`path`对应的`handler.ServeHTTP(rw, req)`，就可以转入f函数的处理逻辑了？???]

2. server创建server := &http.Server{}

   ~~~go
   server := &http.Server{
      Addr:    fmt.Sprintf("%s:%d", s.cfg.YurtHubHost, s.cfg.YurtHubPort),
      Handler: s.mux,
   }
   ~~~

   这里的s.mux在初始化YurtHubServer的时候由mux.NewRouter()产生，这个操作初始化了一个路由列表，之后可以在这个列表上添加路由规则。

   ```go
   // NewYurtHubServer creates a Server object
   func NewYurtHubServer(cfg *config.YurtHubConfiguration,
      certificateMgr interfaces.YurtCertificateManager,
      proxyHandler http.Handler) Server {
      return &yurtHubServer{
         mux:            mux.NewRouter(),
         certificateMgr: certificateMgr,
         proxyHandler:   proxyHandler,
         cfg:            cfg,
      }
   }
   
   // NewRouter returns a new router instance.
   func NewRouter() *Router {
   	return &Router{namedRoutes: make(map[string]*Route)}
   }
   ```

3. server启动

进入`ListenAndServe()`函数：

~~~go
func (srv *Server) ListenAndServe() error {
   if srv.shuttingDown() {
      return ErrServerClosed
   }
   addr := srv.Addr
   if addr == "" {
      addr = ":http"
   }
   // 创建用于监听socket链接，随后将监听的tcp对象传入server
   ln, err := net.Listen("tcp", addr)
   // 启动服务
   return srv.Serve(ln)
}
~~~

进入`srv.Serve(ln)`函数：

主要完成对某个端口进行监听，接收一个刚建立的连接，并发地对每个连接建立一个新服务对象，其中调用Listener的Accept方法用来获取连接数据并使用newConn方法创建连接对象，最后使用goroutein协程的方式处理连接请求，高并发读取每个连接请求并调用`srv.Handler()`去回复这些请求。

```go
func (srv *Server) Serve(l net.Listener) error {
   ...
  
   // 循环监听客户端到来----------------------------------------
   // 在循环中accept，建立connetion,然后处理对应的connection
   for {
      // 调用Accept监听
      rw, err := l.Accept() 
      ...
      connCtx := ctx
      if cc := srv.ConnContext; cc != nil {
         connCtx = cc(connCtx, rw)
         ...
      }
      tempDelay = 0
     // 创建server连接，server连接包含了与客户端通讯的socket以及server相关的信息
      c := srv.newConn(rw)
      // 更新连接状态
      c.setState(c.rwc, StateNew)
     // 启动goroutine处理每个连接
      go c.serve(connCtx) 
   }
}
```

进入`c.serve(connCtx) `函数：

做的事主要是：

- 解析客户端请求
- 选择 multiplexer，如果是 nil 则使用 DefaultServeMux
- 使用 multiplexer 找到请求 uri 所对应的 handler
- 写入 ResponseWriter 并回复给客户端

```go
func (c *conn) serve(ctx context.Context) {
   c.remoteAddr = c.rwc.RemoteAddr().String()
   ctx = context.WithValue(ctx, LocalAddrContextKey, c.rwc.LocalAddr())
   ...

   for {
     	// 读取请求
      w, err := c.readRequest(ctx)
      // 处理读取完毕时候的状态
      if c.r.remain != c.server.initialReadLimitSize() {
         c.setState(c.rwc, StateActive)
      }
     ...

     	// *
      serverHandler{c.server}.ServeHTTP(w, w.req)
      w.cancelCtx()
      if c.hijacked() {
         return
      }
      w.finishRequest() // 请求处理完毕的逻辑 包括w.w.Flush()
      ...
      c.rwc.SetReadDeadline(time.Time{})
   }
}
```

其中` serverHandler{c.server}.ServeHTTP(w, w.req)`完成多路复用器的选择和具体的请求回复操作。

serverHandler结构以及ServeHTTP()函数如下：

```go
type serverHandler struct {
   srv *Server
}

// serverHandler是一个重要的结构，它只有一个字段，即Server结构
// 同时它也实现了Handler接口方法ServeHTTP，并在该接口方法中做了一个重要的事情，初始化multiplexer路由多路复用器。
// 如果server对象没有指定Handler，则使用默认的DefaultServeMux作为路由Multiplexer。
// 并调用初始化Handler的ServeHTTP方法。
func (sh serverHandler) ServeHTTP(rw ResponseWriter, req *Request) {
  // 初始化
	handler := sh.srv.Handler
  // 这个handler由创建http server的时候指定的handler
  //（这里是s.mux也就是由mux.NewRouter()新建的那个map里对应的handler列表）//需要自己添加handler进去吧？？？
	if handler == nil {
    // 使用默认的多路复用器
		handler = DefaultServeMux
	}
	if req.RequestURI == "*" && req.Method == "OPTIONS" {
		handler = globalOptionsHandler{}
	}
  // *
	handler.ServeHTTP(rw, req)
}
```

`handler.ServeHTTP(rw, req)`有不同的实现：

```go
type Handler interface {
   // 实现了寻找注册路由的handler的函数，并调用该handler的ServeHTTP方法。
   // ServeHTTP方法就是真正处理请求和构造响应的地方，这里不同handler类型有不同的实现
   ServeHTTP(ResponseWriter, *Request)
}
```

如果是自定义的多路复用器，则自己构造响应。[（意思是自己往map表里加东西吗？这个过程在哪里？没找到啊）???]

- [这里openyurt是使用自定义的多路复用器？???]

  也就是自己去实现由api路径去匹配handler方法的过程？这个过程在哪里？然后在调用handler方法的ServeHTTP()方法。

  其中api路径和handler方法的注册过程发生在哪里？是`s.mux.PathPrefix("/").Handler(s.proxyHandler)`吗？



- 如果是默认的DefaultServeMux，其ServeHTTP()方法定义在ServeMux结构中：

  mux的ServeHTTP方法通过调用其Handler方法寻找注册到路由上的handler函数，并调用该函数的ServeHTTP方法。

  ~~~go
  func (mux *ServeMux) ServeHTTP(w ResponseWriter, r Request) {
  	if r.RequestURI == "" {
   		if r.ProtoAtLeast(1, 1) {
   			w.Header().Set("Connection", "close")
   		}
   		w.WriteHeader(StatusBadRequest)
   		return
   	}
  	 h, _ := mux.Handler(r) // 依据请求的api路径寻找map中与之对应的真正的处理器函数h
     h.ServeHTTP(w, r)
    // 调用该路由的处理请求的方法
    // 以简单实例为例，这里最终连接到最开始注册给/的IndexHandler()函数，完成处理后返回进行结果的response
  }
  
  func (mux *ServeMux) Handler(r *Request) (h Handler, pattern string) {
   	if r.Method != "CONNECT" {
   		if p := cleanPath(r.URL.Path); p != r.URL.Path {
   			_, pattern = mux.handler(r.Host, p)
   			url := *r.URL
   			url.Path = p
   			return RedirectHandler(url.String(), StatusMovedPermanently), pattern
   		}
   }
   return mux.handler(r.Host, r.URL.Path)
  }
  
  func (mux *ServeMux) handler(host, path string) (h Handler, pattern string) {
   	mux.mu.RLock()
   	defer mux.mu.RUnlock()
  	// Host-specific pattern takes precedence over generic ones
  	if mux.hosts {
     	 h, pattern = mux.match(host + path)
  	}
    if h == nil {
        h, pattern = mux.match(path)
    }
    if h == nil {
        h, pattern = NotFoundHandler(), ""
    }
    return
  }
  
  func (mux *ServeMux) match(path string) (h Handler, pattern string) {
  	var n = 0
  	for k, v := range mux.m {
  		if !pathMatch(k, path) {
  			continue
  		}
  		if h == nil || len(k) > n {
  		n = len(k)
  		h = v.h
  		pattern = v.pattern
  		}
  	}
  	return
  }
  ~~~

  mux的Handler方法对URL简单的处理，然后调用handler方法，后者会创建一个锁，同时调用match方法返回一个handler和pattern。

  在match方法中，mux的m字段是map[string]muxEntry图，后者存储了pattern和handler处理器函数，因此通过迭代m寻找出注册路由的patten模式与实际url匹配的handler函数并返回。

  返回的结构一直传递到mux的ServeHTTP方法，接下来调用handler函数的ServeHTTP方法，即简单实例中的IndexHandler函数，然后把response写到http.RequestWirter对象返回给客户端。

  上述函数运行结束即`serverHandler{c.server}.ServeHTTP(w, w.req)`运行结束。接下来就是对请求处理完毕之后上希望和连接断开的相关逻辑。

至此，一个完整的http服务介绍完毕，包括注册路由，开启监听，处理连接，路由处理函数。



**总结**

多数的web应用基于HTTP协议，客户端和服务器通过request-response的方式交互。一个server并不可少的两部分莫过于路由注册和连接处理。Golang通过一个ServeMux实现了的multiplexer路由多路复用器来管理路由。同时提供一个Handler接口提供ServeHTTP用来实现handler处理其函数，后者可以处理实际request并构造response。

ServeMux和handler处理器函数的连接桥梁就是Handler接口。ServeMux的ServeHTTP方法实现了寻找注册路由的handler的函数，并调用该handler的ServeHTTP方法。ServeHTTP方法就是真正处理请求和构造响应的地方。

总体流程走向：

- 注册路由
- 新建server

- 启动监听服务ListenAndServe()
- 启动服务Serve(ln)
- 接受新建立的连接
- 为每个连接建立一个服务对象
- 服务对象读取连接请求
- 调用srv.Handler.ServeHTTP()处理逻辑
  - 选择多路复用器
  - 执行handler.ServeHTTP()
    - 依据path找handler处理逻辑
    - 执行处理逻辑
- 写入 ResponseWriter 并回复给客户端





## 创建http服务器

创建一个http服务，大致需要经历两个过程：

1. 首先需要**注册路由，即提供url模式和handler函数的映射**

   ```go
   http.HandleFunc("/", indexHandler)
   ```

2. 其次就是**实例化一个server对象，并开启对客户端的监听**

   ```go
   http.ListenAndServe("127.0.0.1:8000", nil)// 使用默认multiplexer
   // 或者：
   server := &Server{Addr: addr, Handler: handler}
   server.ListenAndServe()
   ```



以下参考oy以及ke的源码，具体操作包括：

1. 定义server结构体：在XX Server模块中首先定义一个server的结构体，内容大致包括

   ~~~go
   type ProxyServer struct {
      mux     *mux.Router // 路由表
      handler http.Handler // 处理方法
   }
   ~~~

2. 在Run()函数中注册路由：

   - 一般会为健康检测注册路由：（在healthz函数中一般打印状态信息）

     ~~~go
     s.mux.HandleFunc("/v1/healthz", s.healthz).Methods("GET")
     ps.mux.HandleFunc("/healthz", ps.healthz).Methods("GET")
     ~~~

   - 注册一些debug路由：

     ~~~go
     c.HandleFunc("/debug/pprof/profile", pprof.Profile)
     ~~~

   - 增加URL的前缀：（注意这一条应该是在路由注册的最后）

     ~~~go
     s.mux.PathPrefix("/").Handler(s.proxyHandler)
     ps.mux.PathPrefix("/").Handler(h)
     ~~~

     `PathPrefix()`作用：[???]

     ....

3. 创建http server：

   ~~~go
   server := &http.Server{
       // addr是监听地址，包括ip+端口，具体信息可在server的config相关信息中找到
   		Addr:    fmt.Sprintf("%s:%d", s.cfg.YurtHubHost, s.cfg.YurtHubPort),
       // 注册的路由处理方法
   		Handler: s.mux,
   }
   ~~~

4. 启动http server：

   ~~~go
   err := server.ListenAndServe()
   ~~~

5. 以下内容开始走`/usr/local/go/src/net/http/server.go/ListenAndServer()`函数的逻辑，包括

   - 并发地对每个连接建立一个新服务对象
   - 读取每个连接请求
   - 解析客户端请求
   - 使用多路复用器 multiplexer 找到请求 uri 所对应的 handler
   - 写入 ResponseWriter 并回复给客户端

6. 其中涉及到 *“使用多路复用器 multiplexer <u>找到请求 uri 所对应的 handler</u>”* 的代码是`handler.ServeHTTP(rw, req)`，这需要自己定义

   - 如果是默认的DefaultServeMux，其ServeHTTP方法定义在ServeMux结构中
   - 自定义的路由，则自己实现其ServeHTTP方法





> http server参考：
>
> https://studygolang.com/articles/010298
>
> https://www.jianshu.com/p/be3d9cdc680b
>
> 路由参考：
>
> https://www.cnblogs.com/jiujuan/p/12768907.html
>
> https://www.imooc.com/article/45868







