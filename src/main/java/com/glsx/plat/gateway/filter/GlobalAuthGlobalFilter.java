package com.glsx.plat.gateway.filter;

import com.alibaba.fastjson.JSON;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.glsx.plat.common.utils.StringUtils;
import com.glsx.plat.core.web.R;
import com.glsx.plat.exception.SystemMessage;
import com.glsx.plat.jwt.base.ComJwtUser;
import com.glsx.plat.jwt.config.JwtConfigProperties;
import com.glsx.plat.jwt.util.JwtUtils;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections4.CollectionUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * @author payu
 */
@Slf4j
@Component
@RefreshScope
public class GlobalAuthGlobalFilter implements GlobalFilter, Ordered {

    @Value("${auth.skip.urls}")
    private String[] skipAuthUrls;

    @Autowired
    private JwtConfigProperties properties;

    @Autowired
    private JwtUtils<ComJwtUser> jwtUtils;

    @Autowired
    private StringRedisTemplate stringRedisTemplate;

    @Override
    public int getOrder() {
        return -100;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();

        String url = request.getURI().getPath();
        //跳过不需要验证的路径
        if (Arrays.asList(skipAuthUrls).contains(url)) {
            return chain.filter(exchange);
        }

        //api接口不需要验证
        String[] urlPaths = url.split("/");
        if (!CollectionUtils.sizeIsEmpty(urlPaths)) {
            List<String> list = new ArrayList<>(Arrays.asList(urlPaths));
            if (list.contains("api") || list.contains("API")) {
                return chain.filter(exchange);
            }
        }

        //从请求头中取出token
        String token = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        //未携带token或token在黑名单内
        if (token == null || token.isEmpty() || isBlackToken(token)) {
            log.info("url {} token is empty", url);
            return loginResponse(exchange, token);
        }

        //String serviceName = request.getHeaders().getFirst(Constants.SERVICE_NAME);
        //验证token
        // TODO: 2020/11/5 如果失效会报错，在失效情况下，失效刷新时间范围内，允许刷新
        DecodedJWT decodedJWT = jwtUtils.verify(token);
        if (decodedJWT == null) {
            log.info("url {} token decoded fail", url);
            return loginResponse(exchange, token);
        }

        //判断token是否快要过期或是否已经过期
        if (jwtUtils.isNeedRefreshToken(decodedJWT)) {
            //刷新token
            token = jwtUtils.refreshToken(decodedJWT);
            log.info("refreshed token [{}]", token);
        }

        //log.info("token decoded success {}", decodedJWT.getId());

        ServerHttpRequest mutableReq = appendRequestHeaders(exchange, decodedJWT.getId());

        ServerHttpResponse mutableResp = appendResponseHeaders(exchange, token);

        ServerWebExchange mutableExchange = exchange.mutate()
                .request(mutableReq)
                .response(mutableResp)
                .build();

        return chain.filter(mutableExchange);
    }

    public Mono<Void> loginResponse(ServerWebExchange exchange, String token) {
        ServerHttpResponse originalResponse = exchange.getResponse();
        originalResponse.setStatusCode(HttpStatus.OK);
        originalResponse.getHeaders().add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_UTF8_VALUE);
        originalResponse.getHeaders().add(HttpHeaders.FROM, "Gateway");

        log.info("invalid token [{}]", token);
        String notLoginJson = JSON.toJSONString(R.error(SystemMessage.NOT_LOGIN.getCode(), SystemMessage.NOT_LOGIN.getMsg()));
        byte[] response = notLoginJson.getBytes(StandardCharsets.UTF_8);
        DataBuffer buffer = originalResponse.bufferFactory().wrap(response);
        return originalResponse.writeWith(Flux.just(buffer));
    }

    public ServerHttpRequest appendRequestHeaders(ServerWebExchange exchange, String jwtId) {
//        //将现在的request，添加当前身份
        return exchange.getRequest().mutate()
                .header("Authorization-UserId", jwtId)
                .build();
    }

    public ServerHttpResponse appendResponseHeaders(ServerWebExchange exchange, String token) {
        ServerHttpResponse mutableResp = exchange.getResponse();
        mutableResp.getHeaders().add(HttpHeaders.AUTHORIZATION, token);
        return mutableResp;
    }

    /**
     * 判断token是否在黑名单内
     *
     * @param token
     * @return
     */
    private boolean isBlackToken(String token) {
        assert token != null;
        if (StringUtils.isEmpty(properties.getBlacklistKey())) {
            return false;
        }
        return false;
        //return stringRedisTemplate.hasKey(String.format(properties.getBlacklistKey(), token));
    }

}