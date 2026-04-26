use crate::ir::*;

/// Compute immediate dominators using Cooper-Harvey-Kennedy iterative algorithm.
/// Returns: dom[i] = immediate dominator of block i.
pub fn compute_dominators(cfg: &Cfg) -> Vec<BlockId> {
    let n = cfg.blocks.len();
    if n == 0 {
        return vec![];
    }

    // Build predecessors as Vec<Vec<usize>>
    let mut preds = vec![vec![]; n];
    for block in &cfg.blocks {
        for succ in cfg.successors(block.id) {
            if succ.0 < n {
                preds[succ.0].push(block.id.0);
            }
        }
    }

    let entry = cfg.entry.0;
    let rpo = reverse_postorder(cfg);
    let mut rpo_number = vec![0usize; n];
    for (i, &bid) in rpo.iter().enumerate() {
        rpo_number[bid] = i;
    }

    let undef = usize::MAX;
    let mut idom = vec![undef; n];
    idom[entry] = entry;

    let intersect = |idom: &[usize], rpo_num: &[usize], mut b1: usize, mut b2: usize| -> usize {
        while b1 != b2 {
            while rpo_num[b1] > rpo_num[b2] {
                b1 = idom[b1];
            }
            while rpo_num[b2] > rpo_num[b1] {
                b2 = idom[b2];
            }
        }
        b1
    };

    let mut changed = true;
    while changed {
        changed = false;
        for &b in &rpo {
            if b == entry {
                continue;
            }
            let mut new_idom = undef;
            for &p in &preds[b] {
                if idom[p] == undef {
                    continue;
                }
                if new_idom == undef {
                    new_idom = p;
                } else {
                    new_idom = intersect(&idom, &rpo_number, new_idom, p);
                }
            }
            if new_idom != undef && idom[b] != new_idom {
                idom[b] = new_idom;
                changed = true;
            }
        }
    }

    idom.into_iter()
        .map(|i| BlockId(if i == undef { entry } else { i }))
        .collect()
}

/// Compute post-dominators by running dominators on the reverse CFG.
pub fn compute_post_dominators(cfg: &Cfg) -> Vec<BlockId> {
    let n = cfg.blocks.len();
    if n == 0 {
        return vec![];
    }

    // Find exit blocks
    let exits: Vec<usize> = cfg
        .blocks
        .iter()
        .filter(|b| matches!(b.terminator, Terminator::Return))
        .map(|b| b.id.0)
        .collect();

    let exit_node = exits.first().copied().unwrap_or(n - 1);

    // Build reverse predecessors (forward successors become reverse predecessors)
    let mut rev_preds = vec![vec![]; n];
    for block in &cfg.blocks {
        for succ in cfg.successors(block.id) {
            if succ.0 < n {
                rev_preds[succ.0].push(block.id.0);
            }
        }
    }

    // Reverse postorder on reverse graph
    let mut visited = vec![false; n];
    let mut rpo = Vec::new();
    dfs_collect(exit_node, &rev_preds, &mut visited, &mut rpo);
    rpo.reverse();

    let mut rpo_number = vec![0usize; n];
    for (i, &b) in rpo.iter().enumerate() {
        rpo_number[b] = i;
    }

    let undef = usize::MAX;
    let mut pdom = vec![undef; n];
    pdom[exit_node] = exit_node;

    let intersect = |pdom: &[usize], rpo_num: &[usize], mut b1: usize, mut b2: usize| -> usize {
        while b1 != b2 {
            while rpo_num[b1] > rpo_num[b2] {
                b1 = pdom[b1];
            }
            while rpo_num[b2] > rpo_num[b1] {
                b2 = pdom[b2];
            }
        }
        b1
    };

    let mut changed = true;
    while changed {
        changed = false;
        for &b in &rpo {
            if b == exit_node {
                continue;
            }
            // In reverse graph, successors of b = forward successors
            let mut new_pdom = undef;
            for succ in cfg.successors(BlockId(b)) {
                let s = succ.0;
                if s >= n || pdom[s] == undef {
                    continue;
                }
                if new_pdom == undef {
                    new_pdom = s;
                } else {
                    new_pdom = intersect(&pdom, &rpo_number, new_pdom, s);
                }
            }
            if new_pdom != undef && pdom[b] != new_pdom {
                pdom[b] = new_pdom;
                changed = true;
            }
        }
    }

    pdom.into_iter()
        .map(|i| BlockId(if i == undef { exit_node } else { i }))
        .collect()
}

fn dfs_collect(node: usize, adj: &[Vec<usize>], visited: &mut Vec<bool>, out: &mut Vec<usize>) {
    if node >= visited.len() || visited[node] {
        return;
    }
    visited[node] = true;
    for &next in &adj[node] {
        dfs_collect(next, adj, visited, out);
    }
    out.push(node);
}

fn reverse_postorder(cfg: &Cfg) -> Vec<usize> {
    let n = cfg.blocks.len();
    let mut visited = vec![false; n];
    let mut rpo = Vec::new();

    fn dfs(node: usize, cfg: &Cfg, visited: &mut Vec<bool>, rpo: &mut Vec<usize>) {
        if node >= cfg.blocks.len() || visited[node] {
            return;
        }
        visited[node] = true;
        for succ in cfg.successors(BlockId(node)) {
            dfs(succ.0, cfg, visited, rpo);
        }
        rpo.push(node);
    }

    dfs(cfg.entry.0, cfg, &mut visited, &mut rpo);
    rpo.reverse();
    rpo
}
