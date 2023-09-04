package org.oneedtech.inspect.vc.web;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.oneedtech.inspect.web.InspectorWebConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@SpringBootApplication // == @SpringBootConfiguration @EnableAutoConfiguration @ComponentScan
@Configuration
@Import(InspectorWebConfig.class)
@ComponentScan("org.oneedtech.inspect.web")
public class ValidatorApplication implements WebMvcConfigurer {

	public static void main(String[] args) {
		SpringApplication.run(ValidatorApplication.class, args);
	}

	private final static Logger logger = LogManager.getLogger();
}
