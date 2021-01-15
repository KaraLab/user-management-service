package com.userManagementService.resource;

import com.userManagementService.domain.HttpResponse;
import com.userManagementService.domain.User;
import com.userManagementService.domain.UserPrincipal;
import com.userManagementService.exception.ExceptionHandling;
import com.userManagementService.exception.domain.*;
import com.userManagementService.service.UserService;
import com.userManagementService.utility.JwtTokenProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.*;

import javax.mail.MessagingException;

import java.io.IOException;
import java.util.List;

import static com.userManagementService.constant.EmailConstant.EMAIL_SENT;
import static com.userManagementService.constant.SecurityConstant.JWT_TOKEN_HEADER;
import static org.springframework.http.HttpStatus.NO_CONTENT;
import static org.springframework.http.HttpStatus.OK;

@RestController
@RequestMapping(value = {"/", "/user"})
public class UserResource extends ExceptionHandling {

    private static final String USER_DELETED_SUCCESSFULLY = "User has been deleted successfully";
    private UserService userService;
    private AuthenticationManager authenticationManager;
    private JwtTokenProvider jwtTokenProvider;

    @Autowired
    public UserResource(UserService userService,
                        AuthenticationManager authenticationManager,
                        JwtTokenProvider jwtTokenProvider) {
        this.userService = userService;
        this.authenticationManager = authenticationManager;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @PostMapping("/login")
    public ResponseEntity<User> login(@RequestBody User user) {
        authenticate(user.getUsername(), user.getPassword());
        User loginUser = userService.findUserByUsername(user.getUsername());
        UserPrincipal userPrincipal = new UserPrincipal(loginUser);
        HttpHeaders jwtHeader = getJwtHeader(userPrincipal);
        return new ResponseEntity<>(loginUser, jwtHeader, OK);
    }

    @PostMapping("/register")
    public ResponseEntity<User> register(@RequestBody User user)
            throws UsernameExistException, EmailExistException, MessagingException {
        User newUser = userService.registerUser(user.getFirstName(), user.getLastName(),
                user.getUsername(), user.getEmail());
        return new ResponseEntity<>(newUser, OK);
    }

    @PostMapping("/addUser")
    @PreAuthorize("hasAnyAuthority('user:create')")
    public ResponseEntity<User> addNewUser(@RequestParam("firstName") String firstName,
                                           @RequestParam("lastName") String lastName,
                                           @RequestParam("username") String username,
                                           @RequestParam("email") String email,
                                           @RequestParam("role") String role,
                                           @RequestParam("isActive") String isActive,
                                           @RequestParam("isNotLocked") String isNotLocked)
            throws UserNotFoundException, UsernameExistException, EmailExistException, IOException {
        User newUser = userService.addNewUser(firstName, lastName, username,email, role,
                Boolean.parseBoolean(isNotLocked), Boolean.parseBoolean(isActive));
        return new ResponseEntity<>(newUser, OK);
    }

    @PostMapping("/updateUser")
    @PreAuthorize("hasAnyAuthority('user:update')")
    public ResponseEntity<User> update(@RequestParam("currentUsername") String currentUsername,
                                       @RequestParam("firstName") String firstName,
                                       @RequestParam("lastName") String lastName,
                                       @RequestParam("username") String username,
                                       @RequestParam("email") String email,
                                       @RequestParam("role") String role,
                                       @RequestParam("isActive") String isActive,
                                       @RequestParam("isNonLocked") String isNonLocked)
            throws UserNotFoundException, UsernameExistException, EmailExistException, IOException{
        User updatedUser = userService.updateUser(currentUsername, firstName, lastName, username,email, role,
                Boolean.parseBoolean(isNonLocked), Boolean.parseBoolean(isActive));
        return new ResponseEntity<>(updatedUser, OK);
    }

    @GetMapping("/findUser/{username}")
    public ResponseEntity<User> getUser(@PathVariable("username") String username) {
        User user = userService.findUserByUsername(username);
        return new ResponseEntity<>(user, OK);
    }

    @GetMapping("/listUser")
    public ResponseEntity<List<User>> getAllUsers() {
        List<User> users = userService.getUsers();
        return new ResponseEntity<>(users, OK);
    }

    @GetMapping("/resetpassword/{email}")
    @PreAuthorize("hasAnyAuthority('user:update')")
    public ResponseEntity<HttpResponse> resetPassword(@PathVariable("email") String email)
            throws MessagingException, EmailNotFoundException {
        userService.resetPassword(email);
        return response(NO_CONTENT, EMAIL_SENT + email);
    }

    @DeleteMapping("/delete/{username}")
    @PreAuthorize("hasAnyAuthority('user:delete')")
    public ResponseEntity<HttpResponse> deleteUser(@PathVariable("username") long id) throws IOException {
        userService.deleteUser(id);
        return response(OK, USER_DELETED_SUCCESSFULLY);
    }

    private ResponseEntity<HttpResponse> response(HttpStatus httpStatus, String message) {
        return new ResponseEntity<>(new HttpResponse(httpStatus.value(), httpStatus,
                httpStatus.getReasonPhrase().toUpperCase(), message), httpStatus);
    }

    private HttpHeaders getJwtHeader(UserPrincipal userPrincipal) {
        HttpHeaders header = new HttpHeaders();
        header.add(JWT_TOKEN_HEADER, jwtTokenProvider.generateJwtToken(userPrincipal));
        return header;
    }

    private void authenticate(String username, String password) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
    }
}
