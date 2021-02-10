package com.thehecklers.ssecdemo;

import lombok.*;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.data.repository.CrudRepository;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@SpringBootApplication
public class SsecDemoApplication {
    @Bean
    CommandLineRunner addUsers(UserRepository repo, PasswordEncoder pwEncoder) {
        return args -> {
            repo.saveAll(List.of(new AppUser("mark", pwEncoder.encode("badpass"), "ROLE_USER", true),
                    new AppUser("tiffany", pwEncoder.encode("Better$Password123!"), "ROLE_USER,ROLE_ADMIN", true)));

            repo.findAll().forEach(System.out::println);
        };
    }

    public static void main(String[] args) {
        SpringApplication.run(SsecDemoApplication.class, args);
    }

}

@EnableWebSecurity
class SecConfig {
//    @Bean
//    UserDetailsService authentication() {
//        PasswordEncoder pwEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
//
//        UserDetails mark = User.builder()
//                .username("mark")
//                .password(pwEncoder.encode("badpass"))
//                .roles("USER")
//                .build();
//
//        UserDetails tiffany = User.builder()
//                .username("tiffany")
//                .password(pwEncoder.encode("Better$Password123!"))
//                .roles("USER", "ADMIN")
//                .build();
//
//        System.out.println("   Mark's password: " + mark.getPassword());
//        System.out.println("Tiffany's password: " + tiffany.getPassword());
//
//        return new InMemoryUserDetailsManager(mark, tiffany);
//    }

    @Bean
    PasswordEncoder encoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    SecurityFilterChain authorize(HttpSecurity http) throws Exception {
        return http.authorizeRequests()
                .mvcMatchers("/oneaircraft/**").hasRole("USER")
                .mvcMatchers("/allaircraft/**").hasRole("ADMIN")
                .anyRequest().authenticated()
                .and().formLogin()
                .and().httpBasic()
                .and().build();
    }
}

@RestController
class SecController {
    List<Aircraft> acList = List.of(new Aircraft("N12345", "C172", "DAL->SFO"),
            new Aircraft("N54321", "BE36", "HOU->JFK"),
            new Aircraft("NHECK", "PA28", "STL->LAX"));

    @GetMapping("/")
    String hello() {
        return "Hello out there!";
    }

    @GetMapping("/oneaircraft")
    Aircraft getOneAircraft() {
        return acList.iterator().next();
    }

    @GetMapping("/allaircraft")
    Iterable<Aircraft> getAllAircraft() {
        return acList;
    }
}

@Value
class Aircraft {
    String reg, type, route;
}

class AppUserDetails implements UserDetails {
    private String username, password;
    private boolean isActive;
    private List<GrantedAuthority> roles;

    public AppUserDetails(AppUser user) {
        this.username = user.getUsername();
        this.password = user.getPassword();
        this.isActive = user.isActive();

        this.roles = Stream.of(user.getRoles().split(","))
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return roles;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}

@AllArgsConstructor
@Service
class AppUserDetailsService implements UserDetailsService {
    private final UserRepository repo;

    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        Optional<AppUser> user = repo.findAppUserByUsername(s);

        user.orElseThrow(() -> new UsernameNotFoundException("Invalid user: " + s + "."));

        return user.map(AppUserDetails::new).get();
    }
}

interface UserRepository extends CrudRepository<AppUser, Long> {
    Optional<AppUser> findAppUserByUsername(String username);
}

@Entity
@Data
@NoArgsConstructor
@RequiredArgsConstructor
class AppUser {
    @Id
    @GeneratedValue
    private Long id;
    @NonNull
    private String username, password, roles;
    @NonNull
    private boolean isActive;
}