package com.cos.security1.model;

import com.cos.security1.repository.UserRepository;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.Rollback;
import org.springframework.transaction.annotation.Transactional;

import javax.persistence.EntityManager;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@Transactional
@Rollback(value = false)
class UserTest {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private EntityManager em;

    @Test
    public void userTest01() {
        User user = User.builder()
                .userName("test01")
                .build();

        userRepository.save(user);

        em.flush();
        em.clear();

        User findUser = userRepository.findByUserId(user.getUserId());
        Assertions.assertThat(findUser.getUserName()).isEqualTo(user.getUserName());

    }
}