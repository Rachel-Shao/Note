# APIServer源码分析之启动

本篇主要分析APIServer的启动过程，主要也就是`APIServer.Run()`函数中后半部分所做的事情，参考文献已列出，如有错误欢迎指出！

</br>

## 前言

先来回顾一下`APIServer.Run()`函数的内容：

```go
// Run runs the specified APIServer.  This should never exit.
func Run(completeOptions completedServerRunOptions, stopCh <-chan struct{}) error {
  ...
  // 1.创建了一个server
	server, err := CreateServerChain(completeOptions, stopCh)
	...
  // 2.注册handler，执行hook等，返回一个preparedGenericAPIServer
	prepared, err := server.PrepareRun()
	...
  // 3.启动server
	return prepared.Run(stopCh)
}
```

在上一篇APIServer的创建中，我们知道了`CreateServerChain()`函数所执行的内容，现在server已经创建好，让我们来看看启动的问题。

APIServer涉及启动的主要有：

- `CreateServerChain()`函数结尾的非安全启动`insecureServingInfo.Serve()`
- `server.PrepareRun()`
- `prepared.Run()`

一个一个来看吧~

</br>

## insecureServingInfo.Serve()

回顾一下前文：

~~~go
// CreateServerChain creates the apiservers connected via delegation.
func CreateServerChain(completedOptions completedServerRunOptions, stopCh <-chan struct{}) (*aggregatorapiserver.APIAggregator, error) {
  // 1.创建kubeAPIServerConfig通用配置
  // 2.判断是否配置了扩展API server，创建apiExtensionsConfig配置
  // 3.启动扩展的apiExtensionsserver
  // 4.启动最核心的kubeAPIServer
	// 5.聚合层的配置aggregatorConfig
  // 6.aggregatorServer,聚合服务器，对所有的服务器访问的整合
		...
  // 7.启动非安全端口的server
	if insecureServingInfo != nil {
		insecureHandlerChain := kubeserver.BuildInsecureHandlerChain(aggregatorServer.GenericAPIServer.UnprotectedHandler(), kubeAPIServerConfig.GenericConfig)
    // 启动http服务
		if err := insecureServingInfo.Serve(insecureHandlerChain, kubeAPIServerConfig.GenericConfig.RequestTimeout, stopCh); err != nil {
			return nil, err
		}
	}

  // 8.返回aggregatorServer，后续启动安全端口的server
	return aggregatorServer, nil
}
~~~

`insecureServingInfo.Serve()`这里主要启动非安全端口server，即开启http server。

go语言中开启http服务有很多种方法，比如`http.ListenAndServe`可以直接启动http服务，而这里k8s API server通过自定义http.Server的方式创建http服务：

```go
// Serve starts an insecure http server with the given handler. It fails only if
// the initial listen call fails. It does not block.
func (s *DeprecatedInsecureServingInfo) Serve(handler http.Handler, shutdownTimeout time.Duration, stopCh <-chan struct{}) error {
   // server定义
   insecureServer := &http.Server{
      Addr:           s.Listener.Addr().String(),
      Handler:        handler, 
      MaxHeaderBytes: 1 << 20, //配置请求头的最大字节数
   }

   ...
   // server启动
   _, err := RunServer(insecureServer, s.Listener, shutdownTimeout, stopCh)
   
   return err
}
```

### server定义

其中看到处理器函数为handler，它是由`BuildInsecureHandlerChain()`生成的：

```go
// BuildInsecureHandlerChain sets up the server to listen to http. Should be removed.
func BuildInsecureHandlerChain(apiHandler http.Handler, c *server.Config) http.Handler {
   handler := apiHandler
   
   if c.FlowControl != nil && false {
      handler = genericfilters.WithPriorityAndFairness(handler, c.LongRunningFunc, c.FlowControl)
   } else {
      handler = genericfilters.WithMaxInFlightLimit(handler, c.MaxRequestsInFlight, c.MaxMutatingRequestsInFlight, c.LongRunningFunc)
   }
   handler = genericapifilters.WithAudit(handler, c.AuditBackend, c.AuditPolicyChecker, c.LongRunningFunc)
   handler = genericapifilters.WithAuthentication(handler, server.InsecureSuperuser{}, nil, nil)
   handler = genericfilters.WithCORS(handler, c.CorsAllowedOriginList, nil, nil, nil, "true")
   handler = genericfilters.WithTimeoutForNonLongRunningRequests(handler, c.LongRunningFunc, c.RequestTimeout)
   handler = genericfilters.WithWaitGroup(handler, c.LongRunningFunc, c.HandlerChainWaitGroup)
   handler = genericapifilters.WithRequestInfo(handler, server.NewRequestInfoResolver(c))
   handler = genericapifilters.WithWarningRecorder(handler)
   handler = genericapifilters.WithCacheControl(handler)
   handler = genericfilters.WithPanicRecovery(handler)

   return handler
}
```

且返回的handler基于传入的参数apiHandler，这个参数由`aggregatorServer.GenericAPIServer.UnprotectedHandler()`生成：

```go
func (s *GenericAPIServer) UnprotectedHandler() http.Handler {
   // when we delegate, we need the server we're delegating to choose whether or not to use gorestful
   return s.Handler.Director
}
```

可以看到这个handler是`GenericAPIServer.Handler.Director`的参数内容，其中Director是由GenericAPIServer结构体中Handler参数决定，Handler参数属于APIServerHandler类型，定义如下：

~~~go
type APIServerHandler struct {
    FullHandlerChain   http.Handler
    GoRestfulContainer *restful.Container
    NonGoRestfulMux    *mux.PathRecorderMux
    Director           http.Handler
}
~~~

找到`APIServerHandler`的新建函数：

```go
func NewAPIServerHandler(name string, s runtime.NegotiatedSerializer, handlerChainBuilder HandlerChainBuilderFn, notFoundHandler http.Handler) *APIServerHandler {
   ...
   director := director{
      name:               name,
      goRestfulContainer: gorestfulContainer,
      nonGoRestfulMux:    nonGoRestfulMux,
   }

   return &APIServerHandler{
      FullHandlerChain:   handlerChainBuilder(director),
      GoRestfulContainer: gorestfulContainer,
      NonGoRestfulMux:    nonGoRestfulMux,
      Director:           director,
   }
}
```

这个dector的结构和实现的ServeHTTP()函数如下：

```go
type director struct {
   name               string
   goRestfulContainer *restful.Container
   nonGoRestfulMux    *mux.PathRecorderMux
}

func (d director) ServeHTTP(w http.ResponseWriter, req *http.Request) {
   path := req.URL.Path

   for _, ws := range d.goRestfulContainer.RegisteredWebServices() {
      switch {
      case ws.RootPath() == "/apis":
         if path == "/apis" || path == "/apis/" {
            ...
            d.goRestfulContainer.Dispatch(w, req)
            return
         }

      case strings.HasPrefix(path, ws.RootPath()):
         if len(path) == len(ws.RootPath()) || path[len(ws.RootPath())] == '/' {
            ...
            d.goRestfulContainer.Dispatch(w, req)
            return
         }
      }
   }

   // if we didn't find a match, then we just skip gorestful altogether
   klog.V(5).Infof("%v: %v %q satisfied by nonGoRestful", d.name, req.Method, path)
   d.nonGoRestfulMux.ServeHTTP(w, req)
}
```

其中包含两条解决逻辑：

- **NonGoRestfulMux** 

  不符合Restful风格的请求交由此mux handler处理

  ```go
  // ServeHTTP makes it an http.Handler
  func (m *PathRecorderMux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
     m.mux.Load().(*pathHandler).ServeHTTP(w, r)
  }
  ```

- **GoRestfulContainer** 

  GoRestFulContainer通过Add方法添加webservice，通过Router.selector操作，根据请求选择对应的Route及其所属webservice。

### server启动

回到`insecureServingInfo.Serve()	`，启动服务，进入RunServer()：

```go
func RunServer(
   server *http.Server,
   ln net.Listener,
   shutDownTimeout time.Duration,
   stopCh <-chan struct{},
) (<-chan struct{}, error) {
   ...
   // Shutdown server gracefully.
   stoppedCh := make(chan struct{})
   go func() {
      defer close(stoppedCh)
      <-stopCh
      ctx, cancel := context.WithTimeout(context.Background(), shutDownTimeout)
      server.Shutdown(ctx)
      cancel()
   }()

   go func() {
      defer utilruntime.HandleCrash()

      var listener net.Listener
      listener = tcpKeepAliveListener{ln}
      ...
      // *
      err := server.Serve(listener)

      ...
   }()

   return stoppedCh, nil
}
```

通过`server.Serve()`函数监听listener，在运行过程中为每个连接创建一个协程来读取请求，然后调用Handler函数来处理并响应请求。这一部分之后就开始进入http server的处理流程（回顾http server的处理流程中，调用`ListenAndServe()`之后就会生成listener然后进行`Serve()`，然后完成handler方法匹配，构造响应，回复等流程）

</br>

## server.PrepareRun()

首先通过`PrepareRun`方法完成启动前的路由收尾工作，该方法主要完成了`Swagger`和`OpenAPI`路由的注册工作（`Swagger`和`OpenAPI`主要包含了Kubernetes API的所有细节与规范），并完成/healthz路由的注册工作。

~~~go
// PrepareRun prepares the aggregator to run, by setting up the OpenAPI spec and calling
// the generic PrepareRun.
func (s *APIAggregator) PrepareRun() (preparedAPIAggregator, error) {
	// add post start hook before generic PrepareRun in order to be before /healthz installation
	if s.openAPIConfig != nil {
		s.GenericAPIServer.AddPostStartHookOrDie("apiservice-openapi-controller", func(context genericapiserver.PostStartHookContext) error {
			go s.openAPIAggregationController.Run(context.StopCh)
			return nil
		})
	}

	prepared := s.GenericAPIServer.PrepareRun()

	// delay OpenAPI setup until the delegate had a chance to setup their OpenAPI handlers
	if s.openAPIConfig != nil {
		specDownloader := openapiaggregator.NewDownloader()
		openAPIAggregator, err := openapiaggregator.BuildAndRegisterAggregator(
			&specDownloader,
			s.GenericAPIServer.NextDelegate(),
			s.GenericAPIServer.Handler.GoRestfulContainer.RegisteredWebServices(),
			s.openAPIConfig,
			s.GenericAPIServer.Handler.NonGoRestfulMux)
		if err != nil {
			return preparedAPIAggregator{}, err
		}
		s.openAPIAggregationController = openapicontroller.NewAggregationController(&specDownloader, openAPIAggregator)
	}

	return preparedAPIAggregator{APIAggregator: s, runnable: prepared}, nil
}
~~~

</br>

## prepared.Run()

这里开始最终的server安全启动工作（https）。`Run`方法里通过`NonBlockingRun()`方法启动安全的http server（非安全方式的启动在`CreateServerChain`方法已经完成）。启动https服务的过程和http服务过程类似。

先看`Run()`方法，其中主要内容是在`NonBlockingRun()`中：

（这里怎么连接到`/vendor/k8s.io/apiserver/pkg/server/genericapiserver.go/Run()`未知）

~~~go
// Run生成安全的http服务器。 仅当stopCh关闭或安全端口最初无法监听时，它才返回。
func (s preparedGenericAPIServer) Run(stopCh <-chan struct{}) error {
	...  
  // NonBlockingRun创建一个安全的http server
	stoppedCh, err := s.NonBlockingRun(delayedStopCh)
  
  // -----------------------------------------
  
  // 一直从管道中读取数据，没有数据就阻塞
  // 当stopCh遇到Ctrl+C或者kill来关闭逻辑的时候，这里就会停止阻塞并处理关闭相关逻辑，以达到优雅关闭
	<-stopCh

  // 关闭前执行一些hook操作
	err = s.RunPreShutdownHooks()
	
	<-delayedStopCh
	<-stoppedCh

  // 等待所有请求执行完
	s.HandlerChainWaitGroup.Wait()

	return nil
}
~~~

#### NonBlockingRun()

里面会创建新的 goroutine 最终运行 http 服务器，提供 http 接口给其它 kubernetes 组件调用，也是 kubernetes 集群控制的核心机制

~~~go
func (s preparedGenericAPIServer) NonBlockingRun(stopCh <-chan struct{}) (<-chan struct{}, error) {
	...
	internalStopCh := make(chan struct{})
	
	if s.SecureServingInfo != nil && s.Handler != nil {
		var err error
    // *
		stoppedCh, err = s.SecureServingInfo.Serve(s.Handler, s.ShutdownTimeout, internalStopCh)
		if err != nil {
			close(internalStopCh)
			close(auditStopCh)
			return nil, err
		}
	}

	... // 优雅关闭

	s.RunPostStartHooks(stopCh)

	return stoppedCh, nil
}
~~~

#####  s.SecureServingInfo.Serve()

~~~go
func (s *SecureServingInfo) Serve(handler http.Handler, shutdownTimeout time.Duration, stopCh <-chan struct{}) (<-chan struct{}, error) {
	
	tlsConfig, err := s.tlsConfig(stopCh)

  // 创建了http.Server,里面包含处理 http 请求的 handler，又调用了 RunServer()
	secureServer := &http.Server{
    // 来自用户命令行参数--insecure-bind-address --insecure-port
		Addr:           s.Listener.Addr().String(), 
    // 来自preparedAPIAggregator里的delegateHandler变量
		Handler:        handler, 
		MaxHeaderBytes: 1 << 20,
		TLSConfig:      tlsConfig,
	}

	...
	return RunServer(secureServer, s.Listener, shutdownTimeout, stopCh)
}
~~~

http server和https server的区别在于https server中间增加了用于配置证书的关于TLSConfig的配置，具体在http.Server{}中添加了一行`TLSConfig： tlsConfig`，它的定义如下：

```go
tlsConfig := &tls.Config{
   // Can't use SSLv3 because of POODLE and BEAST
   // Can't use TLSv1.0 because of POODLE and BEAST using CBC cipher
   // Can't use TLSv1.1 because of RC4 cipher usage
   MinVersion: tls.VersionTLS12,
   // enable HTTP2 for go's 1.7 HTTP Server
   NextProtos: []string{"h2", "http/1.1"},
}
```

随后的`RunServer()`转到和非安全启动一样的路线，不再赘述。



