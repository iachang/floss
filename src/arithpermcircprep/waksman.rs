//! A configuration library for Waksman networks.
//!
//! Such a network applies a permutation to sort an input vector.
//!
//! Reference: Waksman network implementation from CirC by Alex Ozdemir, Fraser Brown, and Riad S. Wahby.
//! Source code available at https://github.com/circify/circ/blob/master/circ_waksman/src/lib.rs

use ark_ff::Field;
use fxhash::FxHashSet as HashSet;

/// Apply a permutation to a vector (for testing/verification)
fn apply_permutation<T: Clone>(permutation: &[usize], vec: &[T]) -> Vec<T> {
    assert_eq!(permutation.len(), vec.len());
    permutation.iter().map(|&i| vec[i].clone()).collect()
}
use std::collections::VecDeque;

use std::fmt::Debug;
use std::hash::Hash;

use crate::arithcircop::vector_mul::VectorMul;
use crate::arithcircop::{ArithCircOp, ArithCircState};
use crate::net::Net;
use crate::primitives::auth::AuthShare;

#[derive(Debug, Clone)]
/// A network configuration
pub enum Config {
    /// The trivial configuration for routing 1 flow.
    SingleWire {
        /// The permutation this config implements
        permutation: Vec<usize>,
    },
    /// Routing multiple flows
    Recursive {
        /// The number of flows `n`.
        n_wires: usize,
        /// The permutation this config implements
        permutation: Vec<usize>,
        /// `floor(n/2)` booleans `b_i` indicating whether to switch `2i` and `2i+1` initially
        input_configs: Vec<bool>,
        /// the configuration for the subnet applied to the first output of each initial switch
        upper_subnet: Box<Config>,
        /// the configuration for the subnet applied to all other initial switch outputs (and a
        /// possible final input which doesn't get an initial switch)
        lower_subnet: Box<Config>,
        /// `floor((n-1)/2)` booleans indicating whether to switch outputs `2i` and `2i+1`,
        /// post-subnets.
        output_configs: Vec<bool>,
    },
}

/// Calculate the number of switches needed for a Waksman network with `n_flows` flows.
pub fn n_switches(n_flows: usize) -> usize {
    // (1) of the reference paper
    (1..=n_flows)
        .map(|i| (i as f64).log2().ceil() as usize)
        .sum()
}

impl Config {
    /// Compute the configuration that routes `inputs` into a given permutation.
    pub fn for_permuting<T: Clone + Ord + Hash>(permutation: Vec<usize>) -> Config {
        debug_assert_ne!(permutation.len(), 0);
        if permutation.len() == 1 {
            return Config::SingleWire {
                permutation: permutation.clone(),
            };
        }
        #[cfg(debug_assertions)]
        {
            debug_assert_eq!(
                HashSet::from_iter(permutation.iter()).len(),
                permutation.len()
            );
        }
        let n = permutation.len();
        // two subnets: l and u
        let inv_perm: Vec<usize> = (0..n)
            .map(|i| permutation.iter().position(|&x| x == i).unwrap())
            .collect();

        let n = permutation.len();
        let u_size = n / 2;
        let l_size = n - u_size;
        let n_in_switches = n / 2;
        let n_out_switches = (n - 1) / 2;
        let mut in_l = HashSet::<usize>::default();
        let mut to_place = HashSet::from_iter(0..n);
        // list of forced placements into subnets: [(subnet_idx, output_idx)]
        //    subnet_idx false: l
        //    subnet_idx  true: u
        let mut forced_placements: Vec<(bool, usize)> = vec![(false, n - 1)];
        while !to_place.is_empty() {
            let (subnet_idx, output_i) = forced_placements
                .pop()
                .unwrap_or_else(|| (false, *to_place.iter().next().unwrap()));
            if !to_place.contains(&output_i) {
                debug_assert!(in_l.contains(&output_i) ^ subnet_idx);
            }
            to_place.remove(&output_i);
            if !subnet_idx {
                in_l.insert(output_i);
            }
            if twin(output_i) < n && to_place.contains(&twin(output_i)) {
                forced_placements.push((!subnet_idx, twin(output_i)));
            }
            let input_i = permutation[output_i];
            if twin(input_i) < n {
                let twin_output_i = *inv_perm.get(twin(input_i)).unwrap();
                if to_place.contains(&twin_output_i) {
                    forced_placements.push((!subnet_idx, twin_output_i));
                }
            }
        }
        assert_eq!(in_l.len(), l_size);
        let in_u = HashSet::from_iter((0..n).filter(|i| !in_l.contains(i)));
        let input_configs =
            Vec::from_iter((0..n_in_switches).map(|i| in_l.contains(inv_perm.get(2 * i).unwrap())));
        let output_configs = Vec::from_iter((0..n_out_switches).map(|i| in_l.contains(&(2 * i))));

        let l_permutation = Vec::from_iter(
            (0..n)
                .filter(|i| in_l.contains(i))
                .map(|i| permutation[i] / 2),
        );
        let u_permutation = Vec::from_iter(
            (0..n)
                .filter(|i| in_u.contains(i))
                .map(|i| permutation[i] / 2),
        );

        let lower_subnet = Config::for_permuting::<usize>(l_permutation);
        let upper_subnet = Config::for_permuting::<usize>(u_permutation);
        let ret = Config::Recursive {
            n_wires: n,
            permutation: permutation.clone(),
            input_configs,
            output_configs,
            lower_subnet: Box::new(lower_subnet),
            upper_subnet: Box::new(upper_subnet),
        };
        ret
    }

    /// How many flows does this configuration route?
    pub fn n_flows(&self) -> usize {
        match self {
            Config::SingleWire { .. } => 1,
            Config::Recursive { n_wires, .. } => *n_wires,
        }
    }

    /// Apply this configuration to `data`. If `check` is true, check that the output is sorted,
    /// and print a message/panic if not.
    pub fn apply<T: Clone + Debug + Ord>(&self, data: Vec<T>, check: bool) -> Vec<T> {
        assert_eq!(data.len(), self.n_flows());
        match self {
            Config::SingleWire { .. } => data,
            Config::Recursive {
                n_wires,
                permutation,
                input_configs,
                output_configs,
                upper_subnet,
                lower_subnet,
            } => {
                let data_cp = if check { data.clone() } else { vec![] };
                let mut lower_inputs = Vec::new();
                let mut upper_inputs = Vec::new();
                for i in 0..(n_wires / 2) {
                    let mut first = data[2 * i].clone();
                    let mut second = data[2 * i + 1].clone();
                    if input_configs[i] {
                        std::mem::swap(&mut first, &mut second);
                    }
                    lower_inputs.push(second);
                    upper_inputs.push(first);
                }
                if n_wires % 2 == 1 {
                    lower_inputs.push(data.last().unwrap().clone());
                }
                let mut upper_outputs = upper_subnet.apply(upper_inputs, check);
                let mut lower_outputs = lower_subnet.apply(lower_inputs, check);
                lower_outputs.reverse();
                upper_outputs.reverse();
                let mut outputs = Vec::new();
                for i in 0..((n_wires - 1) / 2) {
                    let mut first = upper_outputs.pop().unwrap();
                    let mut second = lower_outputs.pop().unwrap();
                    if output_configs[i] {
                        std::mem::swap(&mut first, &mut second);
                    }
                    outputs.push(first);
                    outputs.push(second);
                }
                assert!(upper_outputs.len() <= 1);
                assert!(lower_outputs.len() <= 1);
                assert!(!(upper_outputs.len() == 1 && lower_outputs.len() == 0));
                outputs.extend(upper_outputs);
                outputs.extend(lower_outputs);
                if check {
                    let shuffled_test = apply_permutation(permutation, &data_cp);
                    for i in 0..(outputs.len() - 1) {
                        if shuffled_test[i] != outputs[i] {
                            println!("On input {:?}", data_cp[i]);
                            println!("Got ouput {:?}", outputs[i]);
                            println!("Which is not permuted (indices {} {})", i, i);
                            println!("Plan: {:#?}", self);
                            panic!("Config::apply failure");
                        }
                    }
                }
                outputs
            }
        }
    }

    /// Return a list of switch settings.
    pub fn switches(self) -> Vec<bool> {
        let mut out = Vec::new();
        self.switches_into(&mut out);
        out
    }

    fn switches_into(self, into: &mut Vec<bool>) {
        match self {
            Config::SingleWire { .. } => {}
            Config::Recursive {
                input_configs,
                upper_subnet,
                lower_subnet,
                output_configs,
                ..
            } => {
                into.extend(input_configs);
                upper_subnet.switches_into(into);
                lower_subnet.switches_into(into);
                into.extend(output_configs);
            }
        }
    }
}

/// Calculate the opposite wire index for the same switch.
pub fn twin(i: usize) -> usize {
    i ^ 1
}

type SwitchIndex = (usize, bool);

/// Convert a vector of booleans to a vector of switch indices.
pub fn switch_index(switches: Vec<bool>) -> Vec<SwitchIndex> {
    switches
        .iter()
        .enumerate()
        .map(|(i, &switch)| (i, switch))
        .collect()
}

/// Symbolically apply a Waksman network to the given `data`, using the given `switches` and the
/// given `switch_fn`.
pub fn symbolic_apply<T: Clone, Cond, SwitchFn: FnMut(&T, &T, Cond) -> (T, T)>(
    data: Vec<T>,
    switches: &mut VecDeque<Cond>,
    switch_fn: &mut SwitchFn,
) -> Vec<T> {
    let n = data.len();
    if n == 1 {
        return data;
    }
    let n_input_switches = n / 2;
    let n_output_switches = (n - 1) / 2;
    let upper_size = n / 2;
    let lower_size = n - upper_size;
    let mut upper_inputs = Vec::new();
    let mut lower_inputs = Vec::new();
    for input_pair_i in 0..n_input_switches {
        let top_in = &data[2 * input_pair_i];
        let bot_in = &data[2 * input_pair_i + 1];
        let switch = switches.pop_front().unwrap();
        let (top, bot) = switch_fn(top_in, bot_in, switch);
        upper_inputs.push(top);
        lower_inputs.push(bot);
    }
    if n % 2 == 1 {
        lower_inputs.push(data[n - 1].clone());
    }
    let upper_outputs = symbolic_apply(upper_inputs, switches, switch_fn);
    let lower_outputs = symbolic_apply(lower_inputs, switches, switch_fn);
    let mut outputs = Vec::new();
    for output_pair_i in 0..n_output_switches {
        let top_in = &upper_outputs[output_pair_i];
        let bot_in = &lower_outputs[output_pair_i];
        let switch = switches.pop_front().unwrap();
        let (top, bot) = switch_fn(top_in, bot_in, switch);
        outputs.push(top);
        outputs.push(bot);
    }
    if n % 2 == 0 {
        outputs.push(upper_outputs[upper_size - 1].clone());
    }
    outputs.push(lower_outputs[lower_size - 1].clone());
    outputs
}

// TODO: refactor the below into fewer functions
/// Symbolically apply a Waksman network to the given `data`, using the given `switches` and the
/// given `switch_fn`.
pub fn symbolic_apply_circ<F: Field>(
    data: Vec<F>,
    switches: &mut VecDeque<bool>,
    s_in_0_vector: &mut VecDeque<F>,
    s_in_1_vector: &mut VecDeque<F>,
) -> Vec<F> {
    let n = data.len();
    if n == 1 {
        return data;
    }
    let n_input_switches = n / 2;
    let n_output_switches = (n - 1) / 2;
    let upper_size = n / 2;
    let lower_size = n - upper_size;
    let mut upper_inputs = Vec::new();
    let mut lower_inputs = Vec::new();
    for input_pair_i in 0..n_input_switches {
        let top_in = data[2 * input_pair_i];
        let bot_in = data[2 * input_pair_i + 1];
        let switch = switches.pop_front().unwrap();
        let s_in_0 = s_in_0_vector.pop_front().unwrap();
        let s_in_1 = s_in_1_vector.pop_front().unwrap();
        let (top, bot) = if switch {
            (bot_in + s_in_1, top_in + s_in_0)
        } else {
            (top_in + s_in_0, bot_in + s_in_1)
        };
        upper_inputs.push(top);
        lower_inputs.push(bot);
    }
    if n % 2 == 1 {
        lower_inputs.push(data[n - 1].clone());
    }
    let upper_outputs = symbolic_apply_circ(upper_inputs, switches, s_in_0_vector, s_in_1_vector);
    let lower_outputs = symbolic_apply_circ(lower_inputs, switches, s_in_0_vector, s_in_1_vector);
    let mut outputs = Vec::new();
    for output_pair_i in 0..n_output_switches {
        let top_in = upper_outputs[output_pair_i];
        let bot_in = lower_outputs[output_pair_i];
        let switch = switches.pop_front().unwrap();
        let s_in_0 = s_in_0_vector.pop_front().unwrap();
        let s_in_1 = s_in_1_vector.pop_front().unwrap();
        let (top, bot) = if switch {
            (bot_in + s_in_1, top_in + s_in_0)
        } else {
            (top_in + s_in_0, bot_in + s_in_1)
        };
        outputs.push(top);
        outputs.push(bot);
    }
    if n % 2 == 0 {
        outputs.push(upper_outputs[upper_size - 1].clone());
    }
    outputs.push(lower_outputs[lower_size - 1].clone());
    outputs
}

/// Symbolically apply a Waksman network to the given `data`, using the given `switches` and the
/// given `switch_fn`.
pub fn symbolic_apply_circ_rev<F: Field>(
    data: Vec<F>,
    switches: &mut VecDeque<bool>,
    s_out_0_vector: &mut VecDeque<F>,
    s_out_1_vector: &mut VecDeque<F>,
) -> Vec<F> {
    let n = data.len();
    if n == 1 {
        return data;
    }
    let n_input_switches = n / 2;
    let n_output_switches = (n - 1) / 2;
    let upper_size = n / 2;
    let lower_size = n - upper_size;
    let mut upper_outputs = VecDeque::new();
    let mut lower_outputs = VecDeque::new();

    for output_pair_i in (0..n_output_switches).rev() {
        let top_out = data[2 * output_pair_i];
        let bot_out = data[2 * output_pair_i + 1];
        let switch = switches.pop_back().unwrap();
        let s_out_0 = s_out_0_vector.pop_back().unwrap();
        let s_out_1 = s_out_1_vector.pop_back().unwrap();
        let (top, bot) = if switch {
            (bot_out + s_out_1, top_out + s_out_0)
        } else {
            (top_out + s_out_0, bot_out + s_out_1)
        };
        upper_outputs.push_front(top);
        lower_outputs.push_front(bot);
    }
    if n % 2 == 0 {
        upper_outputs.push_back(data[n - 2].clone());
    }
    lower_outputs.push_back(data[n - 1].clone());

    let lower_inputs = symbolic_apply_circ_rev(
        lower_outputs.into_iter().collect(),
        switches,
        s_out_0_vector,
        s_out_1_vector,
    );

    let upper_inputs = symbolic_apply_circ_rev(
        upper_outputs.into_iter().collect(),
        switches,
        s_out_0_vector,
        s_out_1_vector,
    );

    let mut inputs = VecDeque::new();
    for input_pair_i in (0..n_input_switches).rev() {
        let top_out = upper_inputs[input_pair_i];
        let bot_out = lower_inputs[input_pair_i];
        let switch = switches.pop_back().unwrap();
        let s_out_0 = s_out_0_vector.pop_back().unwrap();
        let s_out_1 = s_out_1_vector.pop_back().unwrap();
        let (top, bot) = if switch {
            (bot_out + s_out_1, top_out + s_out_0)
        } else {
            (top_out + s_out_0, bot_out + s_out_1)
        };
        inputs.push_front(bot);
        inputs.push_front(top);
    }
    if n % 2 == 1 {
        inputs.push_back(lower_inputs[lower_size - 1].clone());
    }
    inputs.into_iter().collect()
}

/// Forward circuit
pub fn symbolic_apply_simple<F: Field>(
    net: &mut Net,
    state: &mut ArithCircState<F>,
    data: Vec<AuthShare<F>>,
    switches: &mut VecDeque<AuthShare<F>>,
) -> Vec<AuthShare<F>> {
    let n = data.len();
    if n == 1 {
        return data;
    }

    let n_input_switches = n / 2;
    let n_output_switches = (n - 1) / 2;
    let upper_size = n / 2;
    let lower_size = n - upper_size;

    // ---------- Batch input switches ----------
    let mut sw_in = Vec::with_capacity(n_input_switches);
    let mut delta_top = Vec::with_capacity(n_input_switches); // bot - top
    let mut delta_bot = Vec::with_capacity(n_input_switches); // top - bot

    let mut top_in_vec = Vec::with_capacity(n_input_switches);
    let mut bot_in_vec = Vec::with_capacity(n_input_switches);

    for i in 0..n_input_switches {
        let top_in = data[2 * i].clone();
        let bot_in = data[2 * i + 1].clone();

        let sw = switches.pop_front().unwrap();
        sw_in.push(sw);

        delta_top.push(bot_in.clone() - top_in.clone()); // for top
        delta_bot.push(top_in.clone() - bot_in.clone()); // for bot

        top_in_vec.push(top_in);
        bot_in_vec.push(bot_in);
    }

    // One batched mul for all tops and all bots
    let top_add = VectorMul::<F>::run(net, state, (sw_in.clone(), delta_top));
    let bot_add = VectorMul::<F>::run(net, state, (sw_in, delta_bot));

    let mut upper_inputs = Vec::with_capacity(upper_size);
    let mut lower_inputs = Vec::with_capacity(lower_size);

    for i in 0..n_input_switches {
        upper_inputs.push(top_in_vec[i].clone() + top_add[i].clone());
        lower_inputs.push(bot_in_vec[i].clone() + bot_add[i].clone());
    }
    if n % 2 == 1 {
        lower_inputs.push(data[n - 1].clone());
    }

    // ---------- Recurse ----------
    let upper_outputs = symbolic_apply_simple(net, state, upper_inputs, switches);
    let lower_outputs = symbolic_apply_simple(net, state, lower_inputs, switches);

    // ---------- Batch output switches ----------
    let mut sw_out = Vec::with_capacity(n_output_switches);
    let mut delta_out_top = Vec::with_capacity(n_output_switches); // bot - top
    let mut delta_out_bot = Vec::with_capacity(n_output_switches); // top - bot

    let mut out_top_in_vec = Vec::with_capacity(n_output_switches);
    let mut out_bot_in_vec = Vec::with_capacity(n_output_switches);

    for i in 0..n_output_switches {
        let top_in = upper_outputs[i].clone();
        let bot_in = lower_outputs[i].clone();

        let sw = switches.pop_front().unwrap();
        sw_out.push(sw);

        delta_out_top.push(bot_in.clone() - top_in.clone());
        delta_out_bot.push(top_in.clone() - bot_in.clone());

        out_top_in_vec.push(top_in);
        out_bot_in_vec.push(bot_in);
    }

    let out_top_add = VectorMul::<F>::run(net, state, (sw_out.clone(), delta_out_top));
    let out_bot_add = VectorMul::<F>::run(net, state, (sw_out, delta_out_bot));

    let mut outputs = Vec::with_capacity(n);

    for i in 0..n_output_switches {
        outputs.push(out_top_in_vec[i].clone() + out_top_add[i].clone());
        outputs.push(out_bot_in_vec[i].clone() + out_bot_add[i].clone());
    }

    if n % 2 == 0 {
        outputs.push(upper_outputs[upper_size - 1].clone());
    }
    outputs.push(lower_outputs[lower_size - 1].clone());

    outputs
}

/// Reverse circuit
pub fn symbolic_apply_simple_rev<F: Field>(
    net: &mut Net,
    state: &mut ArithCircState<F>,
    data: Vec<AuthShare<F>>,
    switches: &mut VecDeque<AuthShare<F>>,
) -> Vec<AuthShare<F>> {
    let n = data.len();
    if n == 1 {
        return data;
    }

    let n_input_switches = n / 2;
    let n_output_switches = (n - 1) / 2;
    let upper_size = n / 2;
    let lower_size = n - upper_size;

    // ---------- Batch output switches (reverse order) ----------
    // We must pop switches from the back in the SAME order the original code did.
    // Original iterated output_pair_i in rev and pop_back each time.
    // We'll collect in that same order, then compute, then push_front results.
    let mut sw_out = Vec::with_capacity(n_output_switches);
    let mut delta_top = Vec::with_capacity(n_output_switches); // bot - top
    let mut delta_bot = Vec::with_capacity(n_output_switches); // top - bot

    let mut top_out_vec = Vec::with_capacity(n_output_switches);
    let mut bot_out_vec = Vec::with_capacity(n_output_switches);

    for i in (0..n_output_switches).rev() {
        let top_out = data[2 * i].clone();
        let bot_out = data[2 * i + 1].clone();

        let sw = switches.pop_back().unwrap();
        sw_out.push(sw);

        delta_top.push(bot_out.clone() - top_out.clone());
        delta_bot.push(top_out.clone() - bot_out.clone());

        top_out_vec.push(top_out);
        bot_out_vec.push(bot_out);
    }

    // sw_out/deltas correspond to the reversed loop order; VectorMul returns aligned
    let top_add = VectorMul::<F>::run(net, state, (sw_out.clone(), delta_top));
    let bot_add = VectorMul::<F>::run(net, state, (sw_out, delta_bot));

    let mut upper_outputs = VecDeque::new();
    let mut lower_outputs = VecDeque::new();

    // Iterate in the same order we collected (rev loop order)
    for k in 0..n_output_switches {
        let top = top_out_vec[k].clone() + top_add[k].clone();
        let bot = bot_out_vec[k].clone() + bot_add[k].clone();
        upper_outputs.push_front(top);
        lower_outputs.push_front(bot);
    }

    if n % 2 == 0 {
        upper_outputs.push_back(data[n - 2].clone());
    }
    lower_outputs.push_back(data[n - 1].clone());

    // ---------- Recurse ----------
    let lower_inputs =
        symbolic_apply_simple_rev(net, state, lower_outputs.into_iter().collect(), switches);
    let upper_inputs =
        symbolic_apply_simple_rev(net, state, upper_outputs.into_iter().collect(), switches);

    // ---------- Batch input switches (reverse order) ----------
    let mut sw_in = Vec::with_capacity(n_input_switches);
    let mut delta_in_top = Vec::with_capacity(n_input_switches); // bot - top
    let mut delta_in_bot = Vec::with_capacity(n_input_switches); // top - bot

    let mut top_out_vec2 = Vec::with_capacity(n_input_switches);
    let mut bot_out_vec2 = Vec::with_capacity(n_input_switches);

    for i in (0..n_input_switches).rev() {
        let top_out = upper_inputs[i].clone();
        let bot_out = lower_inputs[i].clone();

        let sw = switches.pop_back().unwrap();
        sw_in.push(sw);

        delta_in_top.push(bot_out.clone() - top_out.clone());
        delta_in_bot.push(top_out.clone() - bot_out.clone());

        top_out_vec2.push(top_out);
        bot_out_vec2.push(bot_out);
    }

    let top_add2 = VectorMul::<F>::run(net, state, (sw_in.clone(), delta_in_top));
    let bot_add2 = VectorMul::<F>::run(net, state, (sw_in, delta_in_bot));

    let mut inputs = VecDeque::new();
    for k in 0..n_input_switches {
        let top = top_out_vec2[k].clone() + top_add2[k].clone();
        let bot = bot_out_vec2[k].clone() + bot_add2[k].clone();
        inputs.push_front(bot);
        inputs.push_front(top);
    }

    if n % 2 == 1 {
        inputs.push_back(lower_inputs[lower_size - 1].clone());
    }

    inputs.into_iter().collect()
}

/// A detailed switch with its index, input indices, and output indices.
#[derive(Clone, Debug)]
pub struct DetailedSwitch {
    /// The index of the first input.
    pub in_0_idx: usize,
    /// The index of the second input.
    pub in_1_idx: usize,
    /// The index of the first output.
    pub out_0_idx: usize,
    /// The index of the second output.
    pub out_1_idx: usize,
}

/// A schedule for a Waksman network.
#[derive(Clone, Debug)]
pub struct WaksmanSchedule {
    /// The switches in the original order.
    pub switches: Vec<DetailedSwitch>,
    /// Each layer is a list of switch indices.
    pub layers: Vec<Vec<usize>>,
    /// The node ids of the final outputs.
    pub outputs: Vec<usize>,
    /// The total node ids (max+1).
    pub n_nodes: usize,
}

/// Symbolically apply the reverse Waksman network to the given `output_data`, using the given `switches` and the
/// given `switch_fn`.
pub fn get_indexed_switches(
    data: Vec<usize>,
    global_index: &mut usize,
    switches_to_return: &mut Vec<DetailedSwitch>,
) -> Vec<usize> {
    let n = data.len();
    if n == 1 {
        return data;
    }
    let n_input_switches = n / 2;
    let n_output_switches = (n - 1) / 2;
    let upper_size = n / 2;
    let lower_size = n - upper_size;
    let mut upper_inputs = Vec::new();
    let mut lower_inputs = Vec::new();
    for input_pair_i in 0..n_input_switches {
        let top_in = &data[2 * input_pair_i];
        let bot_in = &data[2 * input_pair_i + 1];

        *global_index += 1;
        let top_out = *global_index;
        upper_inputs.push(top_out);
        *global_index += 1;
        let bot_out = *global_index;
        lower_inputs.push(bot_out);

        let detailed_switch = DetailedSwitch {
            in_0_idx: *top_in,
            in_1_idx: *bot_in,
            out_0_idx: top_out,
            out_1_idx: bot_out,
        };
        switches_to_return.push(detailed_switch);
    }
    if n % 2 == 1 {
        lower_inputs.push(data[n - 1].clone());
    }
    let upper_outputs =
        get_indexed_switches(upper_inputs.clone(), global_index, switches_to_return);
    let lower_outputs =
        get_indexed_switches(lower_inputs.clone(), global_index, switches_to_return);
    let mut outputs = Vec::new();
    for output_pair_i in 0..n_output_switches {
        let top_in = &upper_outputs[output_pair_i];
        let bot_in = &lower_outputs[output_pair_i];

        *global_index += 1;
        let top_out = *global_index;
        outputs.push(top_out);
        *global_index += 1;
        let bot_out = *global_index;
        outputs.push(bot_out);

        let detailed_switch = DetailedSwitch {
            in_0_idx: *top_in,
            in_1_idx: *bot_in,
            out_0_idx: top_out,
            out_1_idx: bot_out,
        };
        switches_to_return.push(detailed_switch);
    }
    if n % 2 == 0 {
        outputs.push(upper_outputs[upper_size - 1].clone());
    }
    outputs.push(lower_outputs[lower_size - 1].clone());
    outputs
}

/// Build a schedule for a Waksman network.
pub fn build_schedule(n: usize) -> WaksmanSchedule {
    assert!(n >= 1);

    // Initial "wire" ids are 0..n-1
    let data: Vec<usize> = (0..n).collect();

    let mut switches = Vec::<DetailedSwitch>::new();
    let mut global_index = n - 1; // matches your test usage
    let outputs = get_indexed_switches(data, &mut global_index, &mut switches);

    let n_nodes = global_index + 1;

    // node_depth[id] = longest distance (in #switch layers) from inputs to this node
    // inputs 0..n-1 start at depth 0
    let mut node_depth = vec![0usize; n_nodes];

    // switch_depth[s] = depth layer of this switch (>=1)
    let mut switch_depth = vec![0usize; switches.len()];

    // One-pass DP in emitted order: all inputs to a switch must already have node_depth.
    for (sidx, sw) in switches.iter().enumerate() {
        let d0 = node_depth[sw.in_0_idx];
        let d1 = node_depth[sw.in_1_idx];
        let d = 1 + d0.max(d1);

        switch_depth[sidx] = d;

        // outputs are produced at depth d
        node_depth[sw.out_0_idx] = d;
        node_depth[sw.out_1_idx] = d;
    }

    let max_d = *switch_depth.iter().max().unwrap_or(&0);

    let mut layers: Vec<Vec<usize>> = vec![Vec::new(); max_d + 1];
    // layer 0 unused (inputs), switches start at depth >=1
    for (sidx, &d) in switch_depth.iter().enumerate() {
        layers[d].push(sidx);
    }

    // drop layer 0 to make layers[0] be the first switch layer if you prefer
    let layers = layers.into_iter().skip(1).collect();

    WaksmanSchedule {
        switches,
        layers,
        outputs,
        n_nodes,
    }
}

/// Batched DAG
pub fn apply_layer_batched_dag<F: Field>(
    net: &mut Net,
    state: &mut ArithCircState<F>,
    values: &mut [AuthShare<F>],     // indexed by node id
    switches_flat: &[AuthShare<F>],  // indexed by switch index (same as switches vec)
    dag_switches: &[DetailedSwitch], // schedule.switches
    layer_switch_indices: &[usize],  // schedule.layers[L]
) {
    let m = layer_switch_indices.len();
    if m == 0 {
        return;
    }

    let mut sw = Vec::with_capacity(m);
    let mut d_top = Vec::with_capacity(m);
    let mut d_bot = Vec::with_capacity(m);
    let mut xs = Vec::with_capacity(m);
    let mut ys = Vec::with_capacity(m);

    // We also need to remember where outputs go
    let mut out0 = Vec::with_capacity(m);
    let mut out1 = Vec::with_capacity(m);

    for &sidx in layer_switch_indices {
        let ds = &dag_switches[sidx];

        let x = values[ds.in_0_idx].clone();
        let y = values[ds.in_1_idx].clone();
        let s = switches_flat[sidx].clone();

        // cswap arithmetic:
        // top = x + s*(y-x)
        // bot = y + s*(x-y)
        sw.push(s);
        d_top.push(y.clone() - x.clone());
        d_bot.push(x.clone() - y.clone());
        xs.push(x);
        ys.push(y);

        out0.push(ds.out_0_idx);
        out1.push(ds.out_1_idx);
    }

    let add_top = VectorMul::<F>::run(net, state, (sw.clone(), d_top));
    let add_bot = VectorMul::<F>::run(net, state, (sw, d_bot));

    for k in 0..m {
        let new_top = xs[k].clone() + add_top[k].clone();
        let new_bot = ys[k].clone() + add_bot[k].clone();
        values[out0[k]] = new_top;
        values[out1[k]] = new_bot;
    }
}

/// Batched DAG (reverse)
pub fn apply_layer_batched_dag_rev<F: Field>(
    net: &mut Net,
    state: &mut ArithCircState<F>,
    values: &mut [AuthShare<F>],     // indexed by node id
    switches_flat: &[AuthShare<F>],  // indexed by switch index
    dag_switches: &[DetailedSwitch], // schedule.switches
    layer_switch_indices: &[usize],  // schedule.layers[layer]
) {
    let m = layer_switch_indices.len();
    if m == 0 {
        return;
    }

    let mut sw = Vec::with_capacity(m);
    let mut d_top = Vec::with_capacity(m);
    let mut d_bot = Vec::with_capacity(m);

    let mut xs = Vec::with_capacity(m);
    let mut ys = Vec::with_capacity(m);

    // where to write recovered inputs
    let mut in0 = Vec::with_capacity(m);
    let mut in1 = Vec::with_capacity(m);

    for &sidx in layer_switch_indices {
        let ds = &dag_switches[sidx];

        // reverse: we have outputs, want inputs
        let top_out = values[ds.out_0_idx].clone();
        let bot_out = values[ds.out_1_idx].clone();
        let s = switches_flat[sidx].clone();

        // same cswap arithmetic (involution)
        // top_in = top_out + s*(bot_out - top_out)
        // bot_in = bot_out + s*(top_out - bot_out)
        sw.push(s);
        d_top.push(bot_out.clone() - top_out.clone());
        d_bot.push(top_out.clone() - bot_out.clone());
        xs.push(top_out);
        ys.push(bot_out);

        in0.push(ds.in_0_idx);
        in1.push(ds.in_1_idx);
    }

    let add_top = VectorMul::<F>::run(net, state, (sw.clone(), d_top));
    let add_bot = VectorMul::<F>::run(net, state, (sw, d_bot));

    for k in 0..m {
        let top_in = xs[k].clone() + add_top[k].clone();
        let bot_in = ys[k].clone() + add_bot[k].clone();
        values[in0[k]] = top_in;
        values[in1[k]] = bot_in;
    }
}

/// Symbolically apply a Waksman network to the given `inputs`, using the given `switches_flat` and the
pub fn symbolic_apply_batched_log_rounds<F: Field>(
    net: &mut Net,
    state: &mut ArithCircState<F>,
    inputs: Vec<AuthShare<F>>,      // length n
    switches_flat: &[AuthShare<F>], // length == schedule.switches.len()
    schedule: &WaksmanSchedule,
) -> Vec<AuthShare<F>> {
    let n = inputs.len();
    assert!(n >= 1);

    // Allocate all node values
    let mut values = vec![inputs[0].clone(); schedule.n_nodes];

    // Fill input nodes 0..n-1
    for (i, v) in inputs.into_iter().enumerate() {
        values[i] = v;
    }

    // Layer-by-layer evaluation (O(log n) layers)
    for layer in &schedule.layers {
        apply_layer_batched_dag(
            net,
            state,
            &mut values,
            switches_flat,
            &schedule.switches,
            layer,
        );
    }

    // Gather final outputs in the correct order
    schedule
        .outputs
        .iter()
        .map(|&id| values[id].clone())
        .collect()
}

/// Batched DAG (reverse)
pub fn symbolic_apply_batched_log_rounds_rev<F: Field>(
    net: &mut Net,
    state: &mut ArithCircState<F>,
    outputs: Vec<AuthShare<F>>,     // length n
    switches_flat: &[AuthShare<F>], // length == schedule.switches.len()
    schedule: &WaksmanSchedule,
) -> Vec<AuthShare<F>> {
    let n = outputs.len();
    assert!(n >= 1);
    assert_eq!(schedule.outputs.len(), n);

    // Allocate all node values (we only initially know the final outputs)
    let mut values = vec![outputs[0].clone(); schedule.n_nodes];

    // Fill final output nodes with provided outputs
    for (k, &out_id) in schedule.outputs.iter().enumerate() {
        values[out_id] = outputs[k].clone();
    }

    // Evaluate layers from last to first
    for layer in schedule.layers.iter().rev() {
        apply_layer_batched_dag_rev(
            net,
            state,
            &mut values,
            switches_flat,
            &schedule.switches,
            layer,
        );
    }

    // Gather original inputs (node ids 0..n-1)
    (0..n).map(|i| values[i].clone()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use itertools::Itertools;
    use itertools::max;
    use rand::Rng;
    use rand::SeedableRng;
    use rand::seq::SliceRandom;

    /// Get a random permutation of length n
    fn get_random_permutation(n: usize) -> Vec<usize> {
        let mut rng = rand::rng();
        let mut out = (0..n).map(|i| usize::from(i)).collect::<Vec<usize>>();
        out.shuffle(&mut rng);
        out
    }

    fn test_on_data(data: Vec<usize>) {
        let random_permutation = get_random_permutation(data.len());
        let cfg = Config::for_permuting::<usize>(random_permutation);
        cfg.apply(data.clone(), true);
    }

    fn test_all_dense_perms(size: usize) {
        let universe = Vec::from_iter(0..size);
        for data in universe.iter().cloned().permutations(size) {
            test_on_data(data)
        }
    }

    fn test_all_sparse_perms(size: usize) {
        let universe = Vec::from_iter(0..size);
        for data in universe.iter().cloned().permutations(size) {
            test_on_data(data.into_iter().map(|i| 3 * i + 1).collect())
        }
    }

    #[test]
    fn test1_sparse() {
        test_on_data(vec![0]);
        test_on_data(vec![1]);
        test_on_data(vec![17]);
    }

    #[test]
    fn test2_sparse() {
        test_on_data(vec![0, 1]);
        test_on_data(vec![1, 0]);
        test_on_data(vec![1, 2]);
        test_on_data(vec![2, 1]);
        test_on_data(vec![17, 20]);
        test_on_data(vec![20, 10]);
    }

    #[test]
    fn test2_all_dense() {
        test_all_dense_perms(2);
    }

    #[test]
    fn test3_all_dense() {
        test_all_dense_perms(3);
    }

    #[test]
    fn test4_all_dense() {
        test_all_dense_perms(4);
    }

    #[test]
    fn test5_all_dense() {
        test_all_dense_perms(5);
    }

    #[test]
    fn test2_all_sparse() {
        test_all_sparse_perms(2);
    }

    #[test]
    fn test3_all_sparse() {
        test_all_sparse_perms(3);
    }

    #[test]
    fn test4_all_sparse() {
        test_all_sparse_perms(4);
    }

    #[test]
    fn test5_all_sparse() {
        test_all_sparse_perms(5);
    }

    #[test]
    fn test7_all_sparse() {
        test_all_sparse_perms(7);
    }

    #[test]
    fn test3_rev() {
        Config::for_permuting::<usize>(vec![2, 1, 0]);
    }

    #[test]
    fn test5_id() {
        Config::for_permuting::<usize>(vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn test5_transpose() {
        Config::for_permuting::<usize>(vec![1, 0, 2, 3, 4]);
    }

    #[test]
    fn test5_rev() {
        Config::for_permuting::<usize>(vec![4, 3, 2, 1, 0]);
    }

    #[test]
    fn rand_dense_test() {
        let rng = &mut rand_chacha::ChaChaRng::seed_from_u64(0);
        let size = 200;
        let iters = 100;
        for _i in 0..iters {
            let mut data = Vec::from_iter(0..size);
            data.shuffle(rng);
            test_on_data(data);
        }
    }

    #[test]
    fn rand_sparse_rand() {
        let rng = &mut rand_chacha::ChaChaRng::seed_from_u64(0);
        let size = 200;
        let iters = 100;
        for _i in 0..iters {
            let mut data = Vec::from_iter((0..size).map(|i| 10 * i + rng.random_range(0..10)));
            data.shuffle(rng);
            test_on_data(data);
        }
    }

    #[test]
    fn rand_sym_apply() {
        let rng = &mut rand_chacha::ChaChaRng::seed_from_u64(0);
        let size = 200;
        let iters = 10;
        for _i in 0..iters {
            let mut data = Vec::from_iter((0..size).map(|i| 10 * i + rng.random_range(0..10)));
            data.shuffle(rng);
            let random_permutation = get_random_permutation(data.len());
            let cfg = Config::for_permuting::<usize>(random_permutation);
            let apply_normal = cfg.apply(data.clone(), false);
            let mut switches = VecDeque::from_iter(cfg.switches().into_iter());
            dbg!(&switches);
            let apply_sym = symbolic_apply(
                data,
                &mut switches,
                &mut |top: &usize, bot: &usize, cond: bool| {
                    if cond { (*bot, *top) } else { (*top, *bot) }
                },
            );
            assert_eq!(apply_normal, apply_sym);
        }
    }

    #[test]
    fn test_get_indexed_switches() {
        // let random_permutation = vec![1, 0, 3, 2, 4];
        let mut switches_to_return = Vec::new();
        let data = [0, 1, 2, 3, 4];
        let mut global_index = max(data).unwrap();
        let outputs =
            get_indexed_switches(data.to_vec(), &mut global_index, &mut switches_to_return);
        dbg!(switches_to_return.clone(), outputs);
    }
}
