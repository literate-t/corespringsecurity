package io.security.corespringsecurity.service.impl;

import io.security.corespringsecurity.domain.entity.RoleHierarchy;
import io.security.corespringsecurity.repository.RoleHierarchyRepository;
import io.security.corespringsecurity.service.RoleHierarchyService;
import java.util.Iterator;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@RequiredArgsConstructor
@Service
public class RoleHierarchyServiceImpl implements RoleHierarchyService {

  private final RoleHierarchyRepository roleHierarchyRepository;

  @Transactional
  @Override
  public String findAllHierarchy() {

    List<RoleHierarchy> rolesHierarchy = roleHierarchyRepository.findAll();

    Iterator<RoleHierarchy> itr = rolesHierarchy.iterator();
    StringBuffer concatRoles = new StringBuffer();

    while (itr.hasNext()) {
      RoleHierarchy model = itr.next();
      if (model.getParentName() != null) {
        concatRoles.append(model.getParentName().getName());
        concatRoles.append(" > ");
        concatRoles.append(model.getName());
        concatRoles.append("\n");
      }
    }
    return concatRoles.toString();

  }
}