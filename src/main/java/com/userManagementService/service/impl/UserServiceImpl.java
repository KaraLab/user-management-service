package com.userManagementService.service.impl;

import com.userManagementService.domain.User;
import com.userManagementService.domain.UserPrincipal;
import com.userManagementService.enumeration.Role;
import com.userManagementService.exception.domain.EmailExistException;
import com.userManagementService.exception.domain.EmailNotFoundException;
import com.userManagementService.exception.domain.UsernameExistException;
import com.userManagementService.repository.UserRepository;
import com.userManagementService.service.EmailService;
import com.userManagementService.service.LoginAttemptService;
import com.userManagementService.service.UserService;
import org.apache.commons.lang3.RandomStringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import javax.mail.MessagingException;
import javax.transaction.Transactional;

import java.io.IOException;
import java.util.Date;
import java.util.List;

import static com.userManagementService.enumeration.Role.ROLE_USER;
import static com.userManagementService.constant.UserImplConstant.*;

@Service
@Transactional
@Qualifier("userDetailsService")
public class UserServiceImpl implements UserService, UserDetailsService {

    private Logger LOGGER = LoggerFactory.getLogger(getClass());
    private UserRepository userRepository;
    private BCryptPasswordEncoder bCryptPasswordEncoder;
    private LoginAttemptService loginAttemptService;
    private EmailService emailService;

    @Autowired
    public UserServiceImpl(UserRepository userRepository,
                           BCryptPasswordEncoder bCryptPasswordEncoder,
                           LoginAttemptService loginAttemptService,
                           EmailService emailService) {
        this.userRepository = userRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.loginAttemptService = loginAttemptService;
        this.emailService = emailService;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findUserByUsername(username);
        if(user == null) {
            LOGGER.error(NO_USER_FOUND_BY_USERNAME + username);
            throw new UsernameNotFoundException(NO_USER_FOUND_BY_USERNAME + username);
        }else {
            validateLoginAttempt(user);
            LOGGER.info(FOUND_USER_BY_USERNAME + username);
            user.setLastLoginDateDisplay(user.getLastLoginDate());
            user.setLastLoginDate(new Date());
            userRepository.save(user);
            UserPrincipal userPrincipal = new UserPrincipal(user);
            return userPrincipal;
        }
    }

    @Override
    public List<User> getUsers() {
        return userRepository.findAll();
    }

    @Override
    public User findUserByUsername(String username) {
        return userRepository.findUserByUsername(username);
    }

    @Override
    public User findUserByEmail(String email) {
        return userRepository.findUserByEmail(email);
    }

    @Override
    public void deleteUser(long id) {
        userRepository.deleteById(id);
    }

    @Override
    public void resetPassword(String email) throws EmailNotFoundException, MessagingException {
        User user = userRepository.findUserByEmail(email);
        if(user == null) {
            throw new EmailNotFoundException(NO_USER_FOUND_BY_EMAIL + email);
        }
        String password = generatePassword();
        user.setPassword(encodePassword(password));
        userRepository.save(user);
        emailService.sendEmail(user.getFirstName(), user.getUsername(), password, email);
    }

    // to do: refactor creation of user - see methods below
    @Override
    public User registerUser(String firstName, String lastName, String username, String email)
            throws UsernameExistException, EmailExistException, MessagingException {
        validateUsername(username);
        validateEmail(email);

        String password = generatePassword();
        String encodedPassword = encodePassword(password);

        User user = new User();
        user.setUserId(generateUserId());
        user.setFirstName(firstName);
        user.setLastName(lastName);
        user.setUsername(username);
        user.setEmail(email);
        user.setJoinDate(new Date());
        user.setPassword(encodedPassword);
        user.setActive(true);
        user.setNotLocked(true);
        user.setRole(ROLE_USER.name());
        user.setAuthorities(ROLE_USER.getAuthorities());
        userRepository.save(user);

        // For testing purpose
        LOGGER.info("New user password: " + password);

        emailService.sendEmail(firstName, username, password, email);

        return user;
    }

    @Override
    public User updateUser(String currentUsername, String newFirstName, String newLastName, String newUsername,
                           String newEmail, String newRole, boolean isNotBlocked, boolean isActive)
            throws UsernameExistException, EmailExistException {

        User user = userRepository.findUserByUsername(currentUsername);

        if(user == null) {
            throw new UsernameNotFoundException(NO_USER_FOUND_BY_USERNAME + currentUsername);
        }

        if(!newUsername.equalsIgnoreCase(user.getUsername())) {
            validateUsername(newUsername);
        }
        if(!newEmail.equalsIgnoreCase(user.getEmail())) {
            validateEmail(newEmail);
        }

        user.setFirstName(newFirstName);
        user.setLastName(newLastName);
        user.setUsername(newUsername);
        user.setEmail(newEmail);
        user.setActive(isActive);
        user.setNotLocked(isNotBlocked);
        user.setRole(getRoleEnumName(newRole).name());
        user.setAuthorities(getRoleEnumName(newRole).getAuthorities());
        userRepository.save(user);

        return user;
    }

    @Override
    public User addNewUser(String firstName, String lastName, String username, String email, String role, boolean isNotBlocked, boolean isActive) throws UsernameExistException, EmailExistException, IOException {
        validateUsername(username);
        validateEmail(email);

        String password = generatePassword();
        String encodedPassword = encodePassword(password);

        User user = new User();
        user.setUserId(generateUserId());
        user.setFirstName(firstName);
        user.setLastName(lastName);
        user.setUsername(username);
        user.setEmail(email);
        user.setJoinDate(new Date());
        user.setPassword(encodedPassword);
        user.setActive(isActive);
        user.setNotLocked(isNotBlocked);
        user.setRole(getRoleEnumName(role).name());
        user.setAuthorities(getRoleEnumName(role).getAuthorities());
        userRepository.save(user);

        return user;
    }

    private void validateUsername(String username) throws UsernameExistException, EmailExistException {
        if (findUserByUsername(username) != null) {
            throw new UsernameExistException(USERNAME_ALREADY_TAKEN);
        }
    }

    private void validateEmail(String email) throws EmailExistException {
        if (findUserByEmail(email) != null) {
            throw new EmailExistException(EMAIL_ALREADY_TAKEN);
        }
    }

    private void validateLoginAttempt(User user) {
        if(user.isNotLocked()) {
            if(loginAttemptService.hasExceededMaxAttemptCache(user.getUsername())) {
                user.setNotLocked(false);
            }else {
                user.setNotLocked(true);
            }
        }else {
            loginAttemptService.evictUserFromLoginAttemptCache(user.getUsername());
        }
    }

    private String encodePassword(String password) {
        return bCryptPasswordEncoder.encode(password);
    }

    private String generatePassword() {
        return RandomStringUtils.randomAlphanumeric(16);
    }

    private String generateUserId() {
        return RandomStringUtils.randomNumeric(10);
    }

    private Role getRoleEnumName(String role) {
        return Role.valueOf(role.toUpperCase());
    }
}
