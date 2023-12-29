package io.security.corespringsecurity.domain.entity;

import java.util.ArrayList;
import java.util.List;
import lombok.*;

import javax.persistence.*;
import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name="ROLE_HIERARCHY")
@AllArgsConstructor
@NoArgsConstructor
@Data
@Builder
@ToString(exclude = {"parentName", "roleHierarchy"})
public class RoleHierarchy implements Serializable {

  @Id
  @GeneratedValue
  private Long id;

  private String name;

  @ManyToOne(cascade = {CascadeType.ALL},fetch = FetchType.LAZY)
  @JoinColumn(name = "parent_name", referencedColumnName = "name")
  private RoleHierarchy parentName;

  @OneToMany(mappedBy = "parentName", cascade={CascadeType.ALL})
  private List<RoleHierarchy> children = new ArrayList<>();
}