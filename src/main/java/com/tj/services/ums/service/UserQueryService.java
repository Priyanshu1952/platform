package com.tj.services.ums.service;

import com.tj.services.ums.filter.UserFilter;
import com.tj.services.ums.model.User;
import com.tj.services.ums.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class UserQueryService {

    private final UserRepository userRepository;

    public Page<User> findUsers(UserFilter filter) {
        Specification<User> spec = Specification.where(null);

        if (filter.getEmail() != null && !filter.getEmail().isBlank()) {
            spec = spec.and((root, q, cb) -> cb.equal(cb.lower(root.get("email")), filter.getEmail().toLowerCase()));
        }
        if (filter.getMobile() != null && !filter.getMobile().isBlank()) {
            spec = spec.and((root, q, cb) -> cb.equal(root.get("mobile"), filter.getMobile()));
        }
        if (filter.getRole() != null && !filter.getRole().isBlank()) {
            spec = spec.and((root, q, cb) -> cb.equal(root.get("role"), filter.getRole()));
        }
        if (filter.getStatus() != null && !filter.getStatus().isBlank()) {
            spec = spec.and((root, q, cb) -> cb.equal(root.get("status"), filter.getStatus()));
        }
        if (filter.getCreatedFrom() != null) {
            spec = spec.and((root, q, cb) -> cb.greaterThanOrEqualTo(root.get("createdOn"), filter.getCreatedFrom()));
        }
        if (filter.getCreatedTo() != null) {
            spec = spec.and((root, q, cb) -> cb.lessThanOrEqualTo(root.get("createdOn"), filter.getCreatedTo()));
        }

        Sort sort = Sort.by(Sort.Direction.fromString(filter.getSortDir()), filter.getSortBy());
        PageRequest pageReq = PageRequest.of(filter.getPage(), filter.getSize(), sort);
        return userRepository.findAll(spec, pageReq);
    }
} 