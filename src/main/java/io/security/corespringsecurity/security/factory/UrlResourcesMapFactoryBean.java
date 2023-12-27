package io.security.corespringsecurity.security.factory;

import io.security.corespringsecurity.service.SecurityResourceService;
import java.util.LinkedHashMap;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.web.util.matcher.RequestMatcher;

@RequiredArgsConstructor
/**
 * DB로부터 데이터를 가지고와 자원과 권한을 맵핑해주는 객체를 만들어주는 역할
 */
public class UrlResourcesMapFactoryBean implements FactoryBean<LinkedHashMap<RequestMatcher, List<ConfigAttribute>>> {

  private final SecurityResourceService securityResourceService;

  private LinkedHashMap<RequestMatcher, List<ConfigAttribute>> resourceMap;
  @Override
  public LinkedHashMap<RequestMatcher, List<ConfigAttribute>> getObject() throws Exception {

    if (null == resourceMap) {
      resourceMap = getResourceList();
    }

    return resourceMap;
  }

  private LinkedHashMap<RequestMatcher, List<ConfigAttribute>> getResourceList() {
    return securityResourceService.getResourceList();
  }

  @Override
  public Class<?> getObjectType() {
    return LinkedHashMap.class;
  }

  @Override
  public boolean isSingleton() {
    return true;
  }
}
