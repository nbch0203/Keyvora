//! Property tests: three replicas perform random operations and random pairwise syncs (through real encrypted
//! containers). After a final all-to-all exchange every replica must hold the same payload, the merge must be
//! commutative/associative, and **no version may be lost silently**.

use keyvora_sync::{merge_payloads, merge_remote};
use keyvora_vault::model::{compare_clocks, Clock, ClockOrder, ConflictKind};
use keyvora_vault::{Argon2Params, ConflictChoice, EntryInput, Payload, UnlockedVault};
use proptest::prelude::*;

const DEVICES: [&str; 3] = ["dev-a", "dev-b", "dev-c"];
const FAST: Argon2Params = Argon2Params { memory_kib: 19 * 1024, iterations: 2, parallelism: 1 };

#[derive(Debug, Clone)]
enum VKind {
    Live { content: String, updated_at: String, updated_by: String },
    Dead { deleted_at: String, deleted_by: String },
}

#[derive(Debug, Clone)]
struct Version {
    id: String,
    clock: Clock,
    kind: VKind,
}

struct Sim {
    reps: Vec<UnlockedVault>,
    versions: Vec<Version>,
    now: i64,
}

impl Sim {
    fn new() -> Sim {
        let (mut a, _rk) = UnlockedVault::create("correct horse battery", FAST, DEVICES[0], 0).unwrap();
        let c = a.export_container().unwrap();
        let dek = a.export_data_key();
        let b = UnlockedVault::open_with_data_key(&c, &dek, DEVICES[1]).unwrap();
        let cc = UnlockedVault::open_with_data_key(&c, &dek, DEVICES[2]).unwrap();
        Sim { reps: vec![a, b, cc], versions: Vec::new(), now: 1_700_000_000_000 }
    }

    fn tick(&mut self) -> i64 {
        self.now += 1000;
        self.now
    }

    fn record_live(&mut self, r: usize, id: &str) {
        let e = self.reps[r].get_entry(id).unwrap();
        self.versions.push(Version { id: e.id.clone(), clock: e.clock.clone(), kind: VKind::Live { content: e.content_key(), updated_at: e.updated_at.clone(), updated_by: e.updated_by.clone() } });
    }

    fn record_dead(&mut self, r: usize, id: &str) {
        let t = self.reps[r].payload().tombstones.iter().find(|t| t.id == id).unwrap().clone();
        self.versions.push(Version { id: t.id.clone(), clock: t.clock.clone(), kind: VKind::Dead { deleted_at: t.deleted_at.clone(), deleted_by: t.deleted_by.clone() } });
    }

    fn pick(&self, r: usize, n: u8) -> Option<String> {
        let entries = &self.reps[r].payload().entries;
        if entries.is_empty() {
            None
        } else {
            Some(entries[n as usize % entries.len()].id.clone())
        }
    }

    fn apply(&mut self, r: usize, op: u8, n: u8) {
        let now = self.tick();
        match op {
            0 => {
                let input = EntryInput { title: format!("site {n}"), username: format!("user{n}"), password: format!("pw-{now}"), urls: vec![format!("https://s{n}.example.com")], notes: String::new() };
                let e = self.reps[r].create_entry(input, now).unwrap();
                self.record_live(r, &e.id);
            }
            1 | 2 => {
                if let Some(id) = self.pick(r, n) {
                    let cur = self.reps[r].get_entry(&id).unwrap();
                    let input = EntryInput { title: cur.title.clone(), username: format!("{}-{}", DEVICES[r], n), password: format!("pw-{now}-{r}"), urls: cur.urls.clone(), notes: format!("edited at {now}") };
                    self.reps[r].update_entry(&id, input, now).unwrap();
                    self.record_live(r, &id);
                }
            }
            3 => {
                if let Some(id) = self.pick(r, n) {
                    self.reps[r].delete_entry(&id, now).unwrap();
                    self.record_dead(r, &id);
                }
            }
            4 => {
                let with_conflicts: Vec<String> = self.reps[r].payload().entries.iter().filter(|e| !e.conflicts.is_empty()).map(|e| e.id.clone()).collect();
                if let Some(id) = with_conflicts.get(n as usize % with_conflicts.len().max(1)).cloned() {
                    let k = self.reps[r].get_entry(&id).unwrap().conflicts.len();
                    let choice = if n % 2 == 0 { ConflictChoice::KeepCurrent } else { ConflictChoice::TakeConflict(n as usize % k) };
                    self.reps[r].resolve_conflict(&id, choice, now).unwrap();
                    if self.reps[r].get_entry(&id).is_ok() {
                        self.record_live(r, &id);
                    } else {
                        self.record_dead(r, &id);
                    }
                }
            }
            _ => {
                let to = (r + 1 + (n as usize % 2)) % 3;
                self.sync(r, to);
            }
        }
    }

    fn sync(&mut self, from: usize, to: usize) {
        let c = self.reps[from].export_container().unwrap();
        merge_remote(&mut self.reps[to], &c).unwrap();
    }

    fn full_sync(&mut self) {
        for _ in 0..2 {
            for i in 0..3 {
                for j in 0..3 {
                    if i != j {
                        self.sync(i, j);
                    }
                }
            }
        }
    }
}

fn superseded(v: &Version, all: &[Version]) -> bool {
    all.iter().any(|w| w.id == v.id && compare_clocks(&w.clock, &v.clock) == ClockOrder::Greater)
}

fn present(v: &Version, p: &Payload) -> bool {
    let live = p.entries.iter().find(|e| e.id == v.id);
    let dead = p.tombstones.iter().find(|t| t.id == v.id);
    match (&v.kind, live, dead) {
        (VKind::Live { content, updated_at, updated_by }, Some(e), _) => {
            (e.content_key() == *content && compare_clocks(&e.clock, &v.clock) != ClockOrder::Less)
                || e.conflicts.iter().any(|c| c.kind == ConflictKind::Edit && c.sort_key().3 == *content && c.updated_at == *updated_at && c.updated_by == *updated_by)
        }
        (VKind::Dead { .. }, _, Some(t)) => compare_clocks(&t.clock, &v.clock) != ClockOrder::Less,
        (VKind::Dead { deleted_at, deleted_by }, Some(e), _) => {
            e.conflicts.iter().any(|c| c.kind == ConflictKind::Deletion && c.updated_at == *deleted_at && c.updated_by == *deleted_by)
        }
        _ => false,
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 48, .. ProptestConfig::default() })]

    #[test]
    fn replicas_converge_without_loss(ops in prop::collection::vec((0usize..3, 0u8..7, any::<u8>()), 1..45)) {
        let mut sim = Sim::new();
        for (r, op, n) in ops {
            sim.apply(r, op, n);
        }
        // Commutativity / associativity on the (possibly divergent) replica states before the final exchange.
        let (p0, p1, p2) = (sim.reps[0].payload().clone(), sim.reps[1].payload().clone(), sim.reps[2].payload().clone());
        let ab = merge_payloads(&p0, &p1).unwrap().0;
        let ba = merge_payloads(&p1, &p0).unwrap().0;
        prop_assert_eq!(&ab, &ba);
        let left = merge_payloads(&ab, &p2).unwrap().0;
        let bc = merge_payloads(&p1, &p2).unwrap().0;
        let right = merge_payloads(&p0, &bc).unwrap().0;
        prop_assert_eq!(&left, &right);
        prop_assert_eq!(&merge_payloads(&left, &left).unwrap().0, &left); // idempotent

        sim.full_sync();
        let final0 = sim.reps[0].payload().clone();
        prop_assert_eq!(&final0, sim.reps[1].payload());
        prop_assert_eq!(&final0, sim.reps[2].payload());
        prop_assert_eq!(&final0, &left, "pairwise merge must equal the synced result");

        for v in &sim.versions {
            prop_assert!(superseded(v, &sim.versions) || present(v, &final0), "lost version: {:?}", v);
        }
        final0.validate().unwrap();
    }
}
