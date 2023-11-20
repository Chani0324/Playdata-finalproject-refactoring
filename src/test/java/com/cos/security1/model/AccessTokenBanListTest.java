package com.cos.security1.model;

import com.cos.security1.repository.AccessTokenBanListRepository;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import javax.persistence.EntityManager;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class AccessTokenBanListTest {

    @Autowired
    private AccessTokenBanListRepository accessTokenBanListRepository;

    @Autowired
    private EntityManager em;

    @Test
    @Transactional
    public void redisTTLTest() throws InterruptedException {

        // given
        AccessTokenBanList user = AccessTokenBanList.builder()
                .accessToken("test")
                .ttl(5L)
                .build();

        // when
        AccessTokenBanList saveUser = accessTokenBanListRepository.save(user);
        System.out.println("saveUser.getAccessToken() = " + saveUser.getAccessToken());
        System.out.println("saveUser.getTtl() = " + saveUser.getTtl());

        em.flush();
        em.clear();

        List<AccessTokenBanList> all = accessTokenBanListRepository.findAll();
        for (AccessTokenBanList accessTokenBanList : all) {
            System.out.println("accessTokenBanList.toString() = " + accessTokenBanList.toString());
        }

        AccessTokenBanList byAccessToken = accessTokenBanListRepository.findByAccessToken(saveUser.getAccessToken());
        System.out.println("byAccessToken = " + byAccessToken.getAccessToken());

        System.out.println("sleep start");
        Thread.sleep(6000);
        System.out.println("after 6s");


        // then
        Optional<AccessTokenBanList> findUser = Optional.ofNullable(accessTokenBanListRepository
                .findByAccessToken(user.getAccessToken()));

        Assertions.assertThat(findUser).isEmpty();
    }

}