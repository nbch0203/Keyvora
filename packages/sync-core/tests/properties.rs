//! Property tests: three replicas perform random operations and random pairwise syncs (through real encrypted
//! containers). After a final all-to-all exchange every replica must hold the same payload, the merge must be
//! commutative/associative/idempotent, and **no write may be lost silently**: every version ever written is either
//! still present (as the shown version or a pending conflict) or was superseded by a later write whose author had
//! already seen it.

use keyvora_sync::{merge_payloads, merge_remote};
use keyvora_vault::model::{Clock, Dot};
use keyvora_vault::{Argon2Params, ConflictChoice, EntryInput, Payload, UnlockedVault};
use proptest::prelude::*;

const DEVICES: [&str; 3] = ["dev-a", "dev-b", "dev-c"];
const FAST: Argon2Params = Argon2Params { memory_kib: 19 * 1024, iterations: 2, parallelism: 1 };

/// A write as observed right after it happened.
#[derive(Debug, Clone)]
struct Write {
    id: String,
    dot: Dot,
    /// Context of the record on the writing replica right after the write (= everything the author had seen).
    context: Clock,
}

struct Sim {
    reps: Vec<UnlockedVault>,
    writes: Vec<Write>,
    now: i64,
}

impl Sim {
    fn new() -> Sim {
        let (mut a, _rk) = UnlockedVault::create("correct horse battery", FAST, DEVICES[0], 0).unwrap();
        let c = a.export_container().unwrap();
        let dek = a.export_data_key();
        let b = UnlockedVault::open_with_data_key(&c, &dek, DEVICES[1]).unwrap();
        let cc = UnlockedVault::open_with_data_key(&c, &dek, DEVICES[2]).unwrap();
        Sim { reps: vec![a, b, cc], writes: Vec::new(), now: 1_700_000_000_000 }
    }

    fn tick(&mut self) -> i64 {
        self.now += 1000;
        self.now
    }

    /// Records the write just made by replica `r` on record `id`.
    fn record_write(&mut self, r: usize, id: &str) {
        let p = self.reps[r].payload();
        let rec = &p.records[p.record_index(id).unwrap()];
        let counter = rec.context[DEVICES[r]];
        let dot = Dot { device: DEVICES[r].to_owned(), counter };
        assert!(rec.versions.iter().any(|v| v.dot == dot), "write must be present locally");
        self.writes.push(Write { id: id.to_owned(), dot, context: rec.context.clone() });
    }

    fn pick(&self, r: usize, n: u8) -> Option<String> {
        let live: Vec<String> = self.reps[r].list_entries().into_iter().map(|e| e.id).collect();
        (!live.is_empty()).then(|| live[n as usize % live.len()].clone())
    }

    fn apply(&mut self, r: usize, op: u8, n: u8) {
        let now = self.tick();
        match op {
            0 => {
                let input = EntryInput {
                    title: format!("site {n}"),
                    username: format!("user{n}"),
                    password: format!("pw-{now}"),
                    urls: vec![format!("https://s{n}.example.com")],
                    notes: String::new(),
                };
                let e = self.reps[r].create_entry(input, now).unwrap();
                self.record_write(r, &e.id);
            }
            1 | 2 => {
                if let Some(id) = self.pick(r, n) {
                    let cur = self.reps[r].get_entry(&id).unwrap();
                    let input = EntryInput {
                        title: cur.title.clone(),
                        username: format!("{}-{}", DEVICES[r], n),
                        password: format!("pw-{now}-{r}"),
                        urls: cur.urls.clone(),
                        notes: format!("edited at {now}"),
                    };
                    self.reps[r].update_entry(&id, input, now).unwrap();
                    self.record_write(r, &id);
                }
            }
            3 => {
                if let Some(id) = self.pick(r, n) {
                    self.reps[r].delete_entry(&id, now).unwrap();
                    self.record_write(r, &id);
                }
            }
            4 => {
                let with_conflicts: Vec<String> =
                    self.reps[r].list_entries().into_iter().filter(|e| e.has_conflicts).map(|e| e.id).collect();
                if let Some(id) = with_conflicts.get(n as usize % with_conflicts.len().max(1)).cloned() {
                    let k = self.reps[r].get_entry(&id).unwrap().conflicts.len();
                    let choice = if n.is_multiple_of(2) {
                        ConflictChoice::KeepCurrent
                    } else {
                        ConflictChoice::TakeConflict(n as usize % k)
                    };
                    self.reps[r].resolve_conflict(&id, choice, now).unwrap();
                    self.record_write(r, &id);
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

fn superseded(w: &Write, all: &[Write]) -> bool {
    all.iter().any(|x| x.id == w.id && x.dot != w.dot && w.dot.covered_by(&x.context))
}

fn present(w: &Write, p: &Payload) -> bool {
    p.record_index(&w.id).is_some_and(|i| p.records[i].versions.iter().any(|v| v.dot == w.dot))
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, .. ProptestConfig::default() })]

    #[test]
    fn replicas_converge_without_loss(ops in prop::collection::vec((0usize..3, 0u8..7, any::<u8>()), 1..60)) {
        let mut sim = Sim::new();
        for (r, op, n) in ops {
            sim.apply(r, op, n);
        }
        // Algebraic laws on the (possibly divergent) replica states before the final exchange.
        let (p0, p1, p2) = (sim.reps[0].payload().clone(), sim.reps[1].payload().clone(), sim.reps[2].payload().clone());
        let ab = merge_payloads(&p0, &p1).unwrap().0;
        let ba = merge_payloads(&p1, &p0).unwrap().0;
        prop_assert_eq!(&ab, &ba, "commutativity");
        let left = merge_payloads(&ab, &p2).unwrap().0;
        let bc = merge_payloads(&p1, &p2).unwrap().0;
        let right = merge_payloads(&p0, &bc).unwrap().0;
        prop_assert_eq!(&left, &right, "associativity");
        prop_assert_eq!(&merge_payloads(&left, &left).unwrap().0, &left, "idempotence");
        prop_assert_eq!(&merge_payloads(&left, &p1).unwrap().0, &left, "absorption of an older state");

        sim.full_sync();
        let final0 = sim.reps[0].payload().clone();
        prop_assert_eq!(&final0, sim.reps[1].payload(), "convergence b");
        prop_assert_eq!(&final0, sim.reps[2].payload(), "convergence c");
        prop_assert_eq!(&final0, &left, "pairwise merge must equal the synced result");

        for w in &sim.writes {
            prop_assert!(superseded(w, &sim.writes) || present(w, &final0), "lost write: {:?}", w);
        }
        final0.validate().unwrap();
    }
}
