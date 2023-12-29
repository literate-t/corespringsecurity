package io.security.corespringsecurity.security.filter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import org.springframework.security.access.intercept.InterceptorStatusToken;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * 부모 클래스까지(AbstractSecurityInterceptor) 굳이 가지 않고 이 permitAll에 대한 처리를 한다(super.beforeInvocation)
 */
public class PermitAllFilter extends FilterSecurityInterceptor {

  private static final String FILTER_APPLIED = "__spring_security_filterSecurityInterceptor_filterApplied";
  private boolean observeOncePerRequest = true;
  List<RequestMatcher> permitAllRequestMatchers = new ArrayList<>();

  public PermitAllFilter(String... permitAllResources) {
    for (String resource : permitAllResources) {
      permitAllRequestMatchers.add(new AntPathRequestMatcher(resource));
    }
  }

  @Override
  protected InterceptorStatusToken beforeInvocation(Object object) {
    HttpServletRequest request = ((FilterInvocation) object).getRequest();

    for (RequestMatcher matcher : permitAllRequestMatchers) {
      if (matcher.matches(request)) {
        return null;
      }
    }

    return super.beforeInvocation(object);
  }

  public void invoke(FilterInvocation fi) throws IOException, ServletException {
    if ((fi.getRequest() != null)
        && (fi.getRequest().getAttribute(FILTER_APPLIED) != null)
        && observeOncePerRequest) {
      // filter already applied to this request and user wants us to observe
      // once-per-request handling, so don't re-do security checking
      fi.getChain().doFilter(fi.getRequest(), fi.getResponse());
    }
    else {
      // first time this request being called, so perform security checking
      if (fi.getRequest() != null && observeOncePerRequest) {
        fi.getRequest().setAttribute(FILTER_APPLIED, Boolean.TRUE);
      }

      InterceptorStatusToken token = beforeInvocation(fi);

      try {
        fi.getChain().doFilter(fi.getRequest(), fi.getResponse());
      }
      finally {
        super.finallyInvocation(token);
      }

      super.afterInvocation(token, null);
    }
  }
}
