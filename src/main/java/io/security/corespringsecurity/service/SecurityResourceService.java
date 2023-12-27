package io.security.corespringsecurity.service;

import io.security.corespringsecurity.domain.entity.Resources;
import io.security.corespringsecurity.domain.entity.Role;
import io.security.corespringsecurity.repository.ResourcesRepository;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

@RequiredArgsConstructor
public class SecurityResourceService {

  private final ResourcesRepository resourcesRepository;

  public LinkedHashMap<RequestMatcher, List<ConfigAttribute>> getResourceList() {
    LinkedHashMap<RequestMatcher, List<ConfigAttribute>> result = new LinkedHashMap<>();
    List<Resources> resourcesList = resourcesRepository.findAllResources();

    resourcesList.forEach(resources -> {
      List<ConfigAttribute> configAttributeList = new ArrayList<>();

      Set<Role> roleSet = resources.getRoleSet();
      roleSet.forEach(role -> {
        configAttributeList.add(new SecurityConfig(role.getRoleName()));
      });

      result.put(new AntPathRequestMatcher(resources.getResourceName()), configAttributeList);
    });

    return result;
  }
}
