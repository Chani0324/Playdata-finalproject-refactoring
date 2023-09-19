package com.cos.security1.email;


import java.util.Random;

import javax.mail.Message;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.PropertySource;
import org.springframework.mail.MailException;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@PropertySource("classpath:application.yml")
@Slf4j
@AllArgsConstructor
@Service
public class EmailService {
    
    @Autowired
    private JavaMailSender javaMailSender; 
    
    @Autowired
    private UserRepository userRepo;
    
    private MimeMessage createMessage(User user, String authType, String key) throws Exception{
        MimeMessage message = javaMailSender.createMimeMessage();
        
        String registerText = "";
        
        if(authType == "register") { 
            message.addRecipients(Message.RecipientType.TO, user.getUserEmail());
            message.setFrom(new InternetAddress("team3encore@naver.com"));
            message.setSubject("[LYKYL] "+ user.getUserName() + "님 가입을 환영합니다.");
            
            registerText += "<h2>안녕하세요. " +user.getUserName() + "님!</h2>";
            registerText += "<h2>가입을 환영합니다 :)</h2>";
            registerText += "<br/>";
            registerText += "<h3>LYKYL Shop 회원 가입이 완료되었습니다.</h3>";
            registerText += "<h3>지금 바로 LYKYL Shop에 들려 확인하세요!</h3>";
            registerText += "<a href= \"http://localhost:3000/\">"
                    + "<input type= \"button\" value=\"LYKYL Shop 이동하기\""
//            registerText += "<button type=\"button\" onclick=\"window.open(\'http://localhost:3000\')\" "
                    + "style=\"width:200px; height:50px; border-radius:12px; background:black; border:none; "
                    + "color:white; font-size:18px; font-weight:bold;\"></input> </a>";
            registerText += "<br/><br/><hr/>";
            registerText += "<a style=\"color:gray; font-size:12px\">※ 본 메일은 발신전용 메일로 회신을 받을 수 없습니다.</a>";
            
            message.setContent(registerText, "text/html;charset=utf-8");
            
            return message;
            
        }else if (authType == "findid" || authType == "findpw") {
            message.addRecipients(Message.RecipientType.TO, user.getUserEmail());
            message.setSubject("LYKYL 인증번호 전송 메일");
            message.setFrom(new InternetAddress("team3encore@naver.com"));
            
            // 인증코드 이메일 양식 작성안함
            registerText += "<h3>" + user.getUserName() + "님 인증번호를 확인해주세요. <h3/>";
            registerText += "<h4>인증번호 : "+ key + "</h4>";        
            message.setContent(registerText, "text/html;charset=utf-8");
            
            
            return message;
            
        }
        return message;
    }
    
    public static String generateKey() throws Exception {
        int leftLimit = 48; // numeral '0'
        int rightLimit = 122; // letter 'z'
        int targetStringLength = 8;
        Random random = new Random();
        String generatedString = random.ints(leftLimit, rightLimit + 1)
                                       .filter(i -> (i <= 57 || i >= 65) && (i <= 90 || i >= 97))
                                       .limit(targetStringLength)
                                       .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
                                       .toString();
        return generatedString;
    }
    
    public String sendMail(User user, String authType) throws Exception {
        try {
            String key = generateKey();
            MimeMessage mimeMessage = createMessage(user, authType, key);
            javaMailSender.send(mimeMessage);
            
            return key;
        } catch (MailException me) {
            me.printStackTrace();
            throw new IllegalAccessError();
        }
    }
    
}