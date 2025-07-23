package org.cyberwatch.repository;

import org.cyberwatch.model.AttackLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

@Repository
public interface AttackLogRepository extends JpaRepository<AttackLog, Long> {

    List<AttackLog> findBySourceIpOrderByDetectedAtDesc(String sourceIp);

    List<AttackLog> findByAttackTypeOrderByDetectedAtDesc(String attackType);

    List<AttackLog> findByDetectedAtBetweenOrderByDetectedAtDesc(
            LocalDateTime startTime, LocalDateTime endTime);

    @Query("SELECT COUNT(a) FROM AttackLog a WHERE a.detectedAt >= :startTime")
    long countAttacksSince(@Param("startTime") LocalDateTime startTime);

    @Query("SELECT a.attackType, COUNT(a) FROM AttackLog a WHERE a.detectedAt >= :startTime GROUP BY a.attackType")
    List<Object[]> getAttackCountsByType(@Param("startTime") LocalDateTime startTime);

    @Query("SELECT a.sourceIp, COUNT(a) FROM AttackLog a WHERE a.detectedAt >= :startTime GROUP BY a.sourceIp ORDER BY COUNT(a) DESC")
    List<Object[]> getTopSourceIps(@Param("startTime") LocalDateTime startTime);

    List<AttackLog> findTop50ByOrderByDetectedAtDesc();

    List<AttackLog> findBySourceIpAndDetectedAtAfter(String sourceIp, LocalDateTime dateTime);

    long countByAttackType(String attackType);

    long countByBlockedTrueAndDetectedAtAfter(LocalDateTime dateTime);

}
