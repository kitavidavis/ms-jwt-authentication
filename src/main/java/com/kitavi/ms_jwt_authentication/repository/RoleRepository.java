package com.kitavi.ms_jwt_authentication.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.kitavi.ms_jwt_authentication.models.ERole;
import com.kitavi.ms_jwt_authentication.models.Role;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(ERole name);
}
