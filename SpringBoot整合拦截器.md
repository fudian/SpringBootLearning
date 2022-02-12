## 前言
> [拦截器与过滤器的区别，在理解/ 和 /* 的区别_code_mzh的博客-CSDN博客](https://blog.csdn.net/code_mzh/article/details/107196935?utm_medium=distribute.pc_relevant.none-task-blog-2~default~baidujs_title~default-0.pc_relevant_default&spm=1001.2101.3001.4242.1&utm_relevant_index=3)

拦截器通常用来做：登录拦截、或是权限校验、或是防重复提交、或是根据业务像12306去校验购票时间

## 一、基于URL实现的拦截器

```java
public class LoginInterceptor extends HandlerInterceptorAdapter {

	/**
     * 在请求处理之前进行调用（Controller方法调用之前）
     * 基于URL实现的拦截器
     */
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String path = request.getServletPath();
		// public static final String NO_INTERCEPTOR_PATH =".*/((.css)|(.js)|(images)|(login)|(anon)).*";
        if (path.matches(Const.NO_INTERCEPTOR_PATH)) {
        	//不需要的拦截直接过
            return true;
        } else {
        	// 这写你拦截需要干的事儿，比如取缓存，SESSION，权限判断等
            System.out.println("====================================");
            return true;
        }
    }
}
```

`path.matches(Const.NO_INTERCEPTOR_PATH)` 是基于正则匹配的url。
```java
/**
 * @explain 常量类
 */
public class Const {

    public static final String SUCCESS = "SUCCESS";
    public static final String ERROR = "ERROR";
    public static final String FIALL = "FIALL";
    /**********************对象和个体****************************/
    public static final String SESSION_USER = "loginedAgent"; // 用户对象
    public static final String SESSION_LOGINID = "sessionLoginID"; // 登录ID
    public static final String SESSION_USERID = "sessionUserID"; // 当前用户对象ID编号

    public static final String SESSION_USERNAME = "sessionUserName"; // 当前用户对象ID编号
    public static final Integer PAGE = 10; // 默认分页数
    public static final String SESSION_URL = "sessionUrl"; // 被记录的url
    public static final String SESSION_SECURITY_CODE = "sessionVerifyCode"; // 登录页验证码
    // 时间 缓存时间
    public static final int TIMEOUT = 1800;// 秒
	public static final String ON_LOGIN = "/logout.htm";
	public static final String LOGIN_OUT = "/toLogout";
    // 不验证URL anon：不验证/authc：受控制的
    public static final String NO_INTERCEPTOR_PATH =".*/((.css)|(.js)|(images)|(login)|(anon)).*";
}
```

## 二、基于注解的拦截器

**1、创建注解：**
```java
/**
 * 在需要登录验证的Controller的方法上使用此注解
 */
@Target({ElementType.METHOD})// 可用在方法名上
@Retention(RetentionPolicy.RUNTIME)// 运行时有效
public @interface LoginRequired {
}
```

**2、创建拦截器**
```java
public class AuthorityInterceptor extends HandlerInterceptorAdapter{
	
	 @Override
	 public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
	 	// 如果不是映射到方法直接通过
        if (!(handler instanceof HandlerMethod)) {
            return true;
        }
        // ①:START 方法注解级拦截器
        HandlerMethod handlerMethod = (HandlerMethod) handler;
        Method method = handlerMethod.getMethod();
        // 判断接口是否需要登录
        LoginRequired methodAnnotation = method.getAnnotation(LoginRequired.class);
        // 有 @LoginRequired 注解，需要认证
        if (methodAnnotation != null) {
            // 这写你拦截需要干的事儿，比如取缓存，SESSION，权限判断等
            System.out.println("====================================");
            return true;
        }
        return true;
	}
}
```

## 三、把拦截器添加到配置中
这相当于SpringMVC时的配置文件干的事儿
```java
/**
 * 和springmvc的webmvc拦截配置一样
 */
@Configuration
public class WebConfigurer implements WebMvcConfigurer {

	 @Override
	 public void addInterceptors(InterceptorRegistry registry) {
        // 拦截所有请求，通过判断是否有 @LoginRequired 注解 决定是否需要登录
        registry.addInterceptor(LoginInterceptor()).addPathPatterns("/**");
        registry.addInterceptor(AuthorityInterceptor()).addPathPatterns("/**");
	 }
	 
	 @Bean
	 public LoginInterceptor LoginInterceptor() {
		 return new LoginInterceptor();
	 }
	 
	 @Bean
	 public AuthorityInterceptor AuthorityInterceptor() {
		 return new AuthorityInterceptor();
	 }
}
```

1. 一定要加 `@Configuration` 这个注解，在启动的时候在会被加载。
2. 有一些教程是用的 `WebMvcConfigurerAdapter`，不过在spring5.0版本后这个类被丢弃了，虽然还可以用，但是看起来不好。
3. 也有一些教程使用的 WebMvcConfigurationSupport，我使用后发现，classpath:/META/resources/，classpath:/resources/，classpath:/static/，classpath:/public/）不生效。具体可以原因，大家可以看下源码因为：WebMvcAutoConfiguration上有个条件注解：
	```java
	@ConditionalOnMissingBean(WebMvcConfigurationSupport.class)
	```


所以还是建议使用 WebMvcConfigurer， 其实 SpringMVC很多东西，都可以搬到 SpringBoot中来使用，只需要把配置文件的模式，改成对应 `@Configuration` 类就好了。


> [Spring Boot 优雅的配置拦截器方式 - GIT猿【边鹏】博客 - OSCHINA - 中文开源技术交流社区](https://my.oschina.net/bianxin/blog/2876640)


## 分析

1. 拦截器：
	拦截器实现了 `HandlerInterceptor` 接口，重写的 `preHandle` 方法会在 Controller逻辑执行之前拦截所有访问项目 url，并进行自定义操作。（还有另一个方法 postHandle ，会在视图解析前进行拦截）
2. 配置拦截器
	通过实现 WebMvcConfigurer 接口 并实现 addInterceptors方法，通过其参数 InterceptorRegistry 将拦截器注入到 Spring的上下文中。
	另外拦截路径和不拦截的路径通过 InterceptorRegistry 的 addPathPatterns 和 excludePathPatterns 方法进行设置。
	```java
	 @Override
    public void addInterceptors(InterceptorRegistry registry) {
		registry.addInterceptor(loginInterceptor()).addPathPatterns("/**").excludePathPatterns("/*.html");
    }
	```

![](https://raw.githubusercontent.com/fudian/picGo/main/202202052140343.png)

> [SpringBoot之HandlerInterceptor拦截器的使用_liulang68的博客-CSDN博客](https://blog.csdn.net/liulang68/article/details/110631229)