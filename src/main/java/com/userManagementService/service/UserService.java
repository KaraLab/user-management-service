package com.userManagementService.service;

import com.userManagementService.domain.User;
import com.userManagementService.exception.domain.EmailExistException;
import com.userManagementService.exception.domain.EmailNotFoundException;
import com.userManagementService.exception.domain.UsernameExistException;

import javax.mail.MessagingException;
import java.io.IOException;
import java.util.List;

public interface UserService {

    List<User> getUsers();

    User registerUser(String firstName, String lastName, String username, String email) throws UsernameExistException, EmailExistException, MessagingException;

    User findUserByUsername(String username);

    User findUserByEmail(String email);

    User addNewUser(String firstName, String lastName, String username, String email, String role, boolean isNotBlocked, boolean isActive) throws UsernameExistException, EmailExistException, IOException;

    User updateUser(String currentUsername, String newFirstName, String newLastName, String newUsername, String newEmail, String newRole, boolean isNotBlocked, boolean isActive) throws UsernameExistException, EmailExistException, IOException;

    void deleteUser(long id);

    void resetPassword(String email) throws EmailNotFoundException, MessagingException;
}
