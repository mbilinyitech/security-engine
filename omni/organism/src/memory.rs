//! Memory store: decay, reinforcement, consolidation, similarity search.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryItem {
    pub id: u64,
    pub content: String,
    pub embedding: Vec<f64>,
    pub created_ms: i64,
    pub last_access_ms: i64,
    pub access_count: u32,
    pub salience: f64,
    pub emotion: f64,
    pub suppressed: bool,
    pub tombstone: bool,
}

impl MemoryItem {
    fn validate(&self) -> Result<(), String> {
        if self.content.trim().is_empty() {
            return Err(format!("memory {} has empty content", self.id));
        }
        if self.embedding.is_empty() {
            return Err(format!("memory {} has an empty embedding", self.id));
        }
        if self.embedding.iter().any(|value| !value.is_finite()) {
            return Err(format!("memory {} has a non-finite embedding", self.id));
        }
        if !self.salience.is_finite() || !(0.0..=1.0).contains(&self.salience) {
            return Err(format!("memory {} has an out-of-range salience", self.id));
        }
        if !self.emotion.is_finite() || !(-1.0..=1.0).contains(&self.emotion) {
            return Err(format!("memory {} has an out-of-range emotion", self.id));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct MemoryStats {
    pub live: usize,
    pub tombstoned: usize,
    pub suppressed: usize,
    pub capacity: usize,
}

#[derive(Debug, Clone)]
pub struct MemoryStore {
    items: Vec<MemoryItem>,
    next_id: u64,
    capacity: usize,
    decay_per_hour: f64,
    floor: f64,
}

fn cosine(a: &[f64], b: &[f64]) -> f64 {
    let dot: f64 = a.iter().zip(b).map(|(x, y)| x * y).sum();
    let na: f64 = a.iter().map(|x| x * x).sum::<f64>().sqrt();
    let nb: f64 = b.iter().map(|x| x * x).sum::<f64>().sqrt();
    if na == 0.0 || nb == 0.0 {
        0.0
    } else {
        (dot / (na * nb)).clamp(-1.0, 1.0)
    }
}

impl MemoryStore {
    pub fn new(capacity: usize, decay_per_hour: f64, floor: f64) -> Result<Self, String> {
        if capacity == 0 || capacity > 1_000_000 {
            return Err("capacity must be in [1, 1000000]".into());
        }
        if !(decay_per_hour.is_finite() && (0.0..=1.0).contains(&decay_per_hour)) {
            return Err("decay_per_hour must be in [0, 1]".into());
        }
        if !(floor.is_finite() && floor > 0.0 && floor < 1.0) {
            return Err("floor must be in (0, 1)".into());
        }
        Ok(Self {
            items: Vec::new(),
            next_id: 1,
            capacity,
            decay_per_hour,
            floor,
        })
    }

    pub fn snapshot(&self) -> Vec<MemoryItem> {
        self.items.clone()
    }

    pub fn restore(&mut self, items: Vec<MemoryItem>) -> Result<(), String> {
        if items.len() > self.capacity {
            return Err(format!(
                "cannot restore {} items into a capacity of {}",
                items.len(),
                self.capacity
            ));
        }
        let mut seen = std::collections::HashSet::new();
        let mut next_id = 0u64;
        for item in &items {
            item.validate()?;
            if !seen.insert(item.id) {
                return Err(format!("duplicate memory id {}", item.id));
            }
            next_id = next_id.max(item.id.saturating_add(1));
        }
        self.items = items;
        self.next_id = next_id;
        Ok(())
    }

    pub fn insert(
        &mut self,
        content: impl Into<String>,
        embedding: Vec<f64>,
        now_ms: i64,
        salience: f64,
        emotion: f64,
    ) -> Result<u64, String> {
        if embedding.is_empty() {
            return Err("embedding must not be empty".into());
        }
        if embedding.iter().any(|value| !value.is_finite()) {
            return Err("embedding must be finite".into());
        }
        if !(salience.is_finite() && (0.0..=1.0).contains(&salience)) {
            return Err("salience must be in [0, 1]".into());
        }
        if !(emotion.is_finite() && (-1.0..=1.0).contains(&emotion)) {
            return Err("emotion must be in [-1, 1]".into());
        }
        if self.live_count() >= self.capacity {
            self.evict_weakest(now_ms);
        }
        let id = self.next_id;
        self.next_id += 1;
        self.items.push(MemoryItem {
            id,
            content: content.into(),
            embedding,
            created_ms: now_ms,
            last_access_ms: now_ms,
            access_count: 0,
            salience,
            emotion,
            suppressed: false,
            tombstone: false,
        });
        Ok(id)
    }

    pub fn get(&self, id: u64) -> Option<&MemoryItem> {
        self.items.iter().find(|item| item.id == id)
    }

    /// Exponential decay from the last access, amplified by reinforcement.
    pub fn strength(&self, id: u64, now_ms: i64) -> Result<f64, String> {
        let item = self
            .items
            .iter()
            .find(|item| item.id == id)
            .ok_or_else(|| format!("unknown memory id {id}"))?;
        Ok(self.strength_of(item, now_ms))
    }

    fn strength_of(&self, item: &MemoryItem, now_ms: i64) -> f64 {
        let hours = ((now_ms - item.last_access_ms).max(0) as f64) / 3_600_000.0;
        let decay = (-self.decay_per_hour * hours).exp();
        let reinforcement = 1.0 + (1.0 + item.access_count as f64).ln() * 0.2;
        (item.salience * decay * reinforcement).clamp(0.0, 1.0)
    }

    pub fn reinforce(&mut self, id: u64, now_ms: i64) -> Result<(), String> {
        let item = self
            .items
            .iter_mut()
            .find(|item| item.id == id)
            .ok_or_else(|| format!("unknown memory id {id}"))?;
        item.access_count = item.access_count.saturating_add(1);
        item.last_access_ms = now_ms;
        Ok(())
    }

    /// Forget everything that fell below the floor. Returns how many items went.
    pub fn decay_sweep(&mut self, now_ms: i64) -> usize {
        let floor = self.floor;
        let mut forgotten = 0;
        for item in self.items.iter_mut() {
            if item.tombstone || item.suppressed {
                continue;
            }
            let hours = ((now_ms - item.last_access_ms).max(0) as f64) / 3_600_000.0;
            let decay = (-self.decay_per_hour * hours).exp();
            let reinforcement = 1.0 + (1.0 + item.access_count as f64).ln() * 0.2;
            let strength = (item.salience * decay * reinforcement).clamp(0.0, 1.0);
            if strength < floor {
                item.tombstone = true;
                forgotten += 1;
            }
        }
        forgotten
    }

    /// Merge near-duplicates into the stronger item (sleep consolidation).
    pub fn consolidate(&mut self, threshold: f64, now_ms: i64) -> Result<usize, String> {
        if !(threshold.is_finite() && threshold > 0.0 && threshold <= 1.0) {
            return Err("threshold must be in (0, 1]".into());
        }
        if self.live_count() > 5_000 {
            return Err("consolidate is limited to 5000 live items".into());
        }
        let mut merged = 0usize;
        let mut alive: Vec<usize> = self
            .items
            .iter()
            .enumerate()
            .filter(|(_, item)| !item.tombstone)
            .map(|(index, _)| index)
            .collect();
        alive.sort_by_key(|index| {
            std::cmp::Reverse(self.items[*index].salience.to_bits())
        });
        for position in 0..alive.len() {
            let keeper = alive[position];
            if self.items[keeper].tombstone {
                continue;
            }
            for other in alive.iter().skip(position + 1) {
                if self.items[*other].tombstone {
                    continue;
                }
                if self.items[keeper].embedding.len() != self.items[*other].embedding.len() {
                    continue;
                }
                let similarity = cosine(
                    &self.items[keeper].embedding,
                    &self.items[*other].embedding,
                );
                if similarity < threshold {
                    continue;
                }
                let absorbed = self.items[*other].clone();
                let keeper_item = &mut self.items[keeper];
                keeper_item.access_count = keeper_item
                    .access_count
                    .saturating_add(absorbed.access_count + 1);
                keeper_item.last_access_ms = keeper_item.last_access_ms.max(now_ms);
                for (slot, value) in keeper_item
                    .embedding
                    .iter_mut()
                    .zip(absorbed.embedding.iter())
                {
                    *slot = (*slot + *value) / 2.0;
                }
                self.items[*other].tombstone = true;
                merged += 1;
            }
        }
        Ok(merged)
    }

    pub fn search_similar(
        &self,
        query: &[f64],
        limit: usize,
        now_ms: i64,
    ) -> Result<Vec<(u64, f64)>, String> {
        if query.is_empty() || query.iter().any(|value| !value.is_finite()) {
            return Err("query embedding must be finite and non-empty".into());
        }
        if limit == 0 {
            return Err("limit must be positive".into());
        }
        let mut scored: Vec<(u64, f64)> = self
            .items
            .iter()
            .filter(|item| !item.tombstone && !item.suppressed)
            .filter(|item| item.embedding.len() == query.len())
            .map(|item| {
                let score = cosine(query, &item.embedding) * self.strength_of(item, now_ms);
                (item.id, score)
            })
            .filter(|(_, score)| *score > 0.0)
            .collect();
        scored.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.0.cmp(&b.0)));
        scored.truncate(limit);
        Ok(scored)
    }

    pub fn search_by_time(&self, from_ms: i64, to_ms: i64) -> Vec<u64> {
        let mut ids: Vec<u64> = self
            .items
            .iter()
            .filter(|item| !item.tombstone)
            .filter(|item| item.created_ms >= from_ms && item.created_ms <= to_ms)
            .map(|item| item.id)
            .collect();
        ids.sort_unstable();
        ids
    }

    pub fn search_by_emotion(&self, min: f64, max: f64) -> Vec<u64> {
        let mut ids: Vec<u64> = self
            .items
            .iter()
            .filter(|item| !item.tombstone)
            .filter(|item| item.emotion >= min && item.emotion <= max)
            .map(|item| item.id)
            .collect();
        ids.sort_unstable();
        ids
    }

    pub fn suppress(&mut self, id: u64, suppressed: bool) -> Result<(), String> {
        let item = self
            .items
            .iter_mut()
            .find(|item| item.id == id)
            .ok_or_else(|| format!("unknown memory id {id}"))?;
        item.suppressed = suppressed;
        Ok(())
    }

    /// Explicit forgetting keeps a tombstone: the organism knows it forgot.
    pub fn forget(&mut self, id: u64) -> Result<(), String> {
        let item = self
            .items
            .iter_mut()
            .find(|item| item.id == id)
            .ok_or_else(|| format!("unknown memory id {id}"))?;
        item.tombstone = true;
        Ok(())
    }

    /// True deletion of tombstones (cannot be undone, unlike `forget`).
    pub fn purge(&mut self) -> usize {
        let before = self.items.len();
        self.items.retain(|item| !item.tombstone);
        before - self.items.len()
    }

    pub fn stats(&self) -> MemoryStats {
        MemoryStats {
            live: self.live_count(),
            tombstoned: self.items.iter().filter(|item| item.tombstone).count(),
            suppressed: self.items.iter().filter(|item| item.suppressed).count(),
            capacity: self.capacity,
        }
    }

    fn live_count(&self) -> usize {
        self.items.iter().filter(|item| !item.tombstone).count()
    }

    fn evict_weakest(&mut self, now_ms: i64) {
        let mut weakest: Option<(usize, f64)> = None;
        for (index, item) in self.items.iter().enumerate() {
            if item.tombstone || item.suppressed {
                continue;
            }
            let strength = self.strength_of(item, now_ms);
            if weakest.is_none_or(|(_, best)| strength < best) {
                weakest = Some((index, strength));
            }
        }
        if let Some((index, _)) = weakest {
            self.items[index].tombstone = true;
        }
    }
}
