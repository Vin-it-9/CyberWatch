package org.cyberwatch.service;

import org.cyberwatch.model.AttackLog;
import org.cyberwatch.repository.AttackLogRepository;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.concurrent.CompletableFuture;

@Service
public class AttackLogBatchService {

    private final AttackLogRepository repo;

    public AttackLogBatchService(AttackLogRepository repo) { this.repo = repo; }

    @Async
    @Transactional
    public CompletableFuture<Void> persist(List<AttackLog> batch) {
        repo.saveAll(batch);
        return CompletableFuture.completedFuture(null);
    }
}

