package org.cyberwatch;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
@EnableAsync
@EnableCaching
public class CyberWatchApplication {

	public static void main(String[] args) {
		SpringApplication.run(CyberWatchApplication.class, args);

		System.out.println("CyberWatch is running! Visit http://localhost:8080 to access the application.");
		System.out.println("To access the API, use the following URL: http://localhost:8080/api/v1/scan");
		System.out.println("For Swagger documentation, visit: http://localhost:8080/swagger-ui/index.html");
		System.out.println("IP address: " + java.net.InetAddress.getLoopbackAddress().getHostAddress());




	}

}
