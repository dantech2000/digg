//! Running one query per item across scoped threads.
//!
//! The comparison, propagation and batch modes all fan out the same way: spawn
//! a worker per item, join them in input order, and turn a panicking worker
//! into an error for that item instead of losing the whole run. That is three
//! copies of the same concurrency handling, which is the kind of thing worth
//! having exactly one of.

/// Apply `f` to every item on scoped threads, at most `max_parallel` at a time.
///
/// Results come back in input order. A worker that panics yields `None` for its
/// item rather than propagating, so one bad query cannot take down the run;
/// callers turn that into whatever "this one failed" means for them.
///
/// `max_parallel` bounds how many threads exist at once, which matters for
/// batch files that can hold thousands of queries. Pass `usize::MAX` for one
/// thread per item.
pub fn map<T, R>(items: &[T], max_parallel: usize, f: impl Fn(&T) -> R + Sync) -> Vec<Option<R>>
where
    T: Sync,
    R: Send,
{
    let mut results = Vec::with_capacity(items.len());
    // chunks() panics on 0, and a zero-width batch would never make progress.
    for chunk in items.chunks(max_parallel.max(1)) {
        std::thread::scope(|scope| {
            let handles: Vec<_> = chunk.iter().map(|item| scope.spawn(|| f(item))).collect();
            for handle in handles {
                results.push(handle.join().ok());
            }
        });
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn results_come_back_in_input_order() {
        let items: Vec<u32> = (0..50).collect();
        let doubled = map(&items, 8, |n| n * 2);
        let doubled: Vec<u32> = doubled.into_iter().map(|r| r.unwrap()).collect();
        assert_eq!(doubled, items.iter().map(|n| n * 2).collect::<Vec<_>>());
    }

    #[test]
    fn a_panicking_worker_becomes_none_and_the_rest_still_run() {
        let items: Vec<u32> = (0..10).collect();
        let out = map(&items, 4, |n| {
            assert_ne!(*n, 7, "deliberate panic in a worker");
            *n
        });
        assert_eq!(out[7], None, "the panicking item yields None");
        for (i, r) in out.iter().enumerate() {
            if i != 7 {
                assert_eq!(*r, Some(i as u32), "item {} should be unaffected", i);
            }
        }
    }

    #[test]
    fn chunking_bounds_concurrency_without_dropping_items() {
        let items: Vec<u32> = (0..37).collect();
        assert_eq!(map(&items, 8, |n| *n).len(), 37);
        assert_eq!(map(&items, usize::MAX, |n| *n).len(), 37);
        // A zero limit must still make progress rather than panicking.
        assert_eq!(map(&items, 0, |n| *n).len(), 37);
    }

    #[test]
    fn an_empty_input_spawns_nothing() {
        let items: Vec<u32> = Vec::new();
        assert!(map(&items, 8, |n| *n).is_empty());
    }
}
