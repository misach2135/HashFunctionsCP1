use core::{fmt};
use std::{borrow::Cow, cell::Cell, collections::{hash_map, HashMap, HashSet}, fs::File, io::{BufWriter, Write}, ops::Add};
use rand::{random, thread_rng, Rng};
use std::time::{Duration, Instant};

use sha3::{Digest, Sha3_224};

#[derive(Debug)]
struct AttackResult {
    iterations_count: u64,
    collision: (String, String)
}

trait StringModificator<'a> {
    fn from_str(s: &'a str) -> Self;
    fn modify(&mut self) -> String;
    fn modifyDebug(&self) -> (String, usize) {
        (String::new(), 0)
    }
}
// TODO: check for ascii
struct AdditionStringModifier<'a> {
    data: &'a str,
    state: Cell<u64>
}

// TODO: check for ascii
struct RandomChangeStringModifier {
    data: String
}

impl<'a> AdditionStringModifier<'a> {
    fn new(data: &'a str, init_state: u64) -> AdditionStringModifier<'a> {
        let cell = Cell::new(init_state);
        AdditionStringModifier {
            data,
            state: cell
        }
    }
}

impl<'a> RandomChangeStringModifier {
    fn new(data: &'a str) -> RandomChangeStringModifier {
        RandomChangeStringModifier {
            data: data.to_owned()
        }
    }
}

impl<'a> StringModificator<'a> for AdditionStringModifier<'a> {
    fn modify(&mut self) -> String {
        let mut res = String::from(self.data);
        res.push_str(&self.state.get().to_string());
        self.state.set(self.state.get() + 1);
        res
    }
    
    fn from_str(s: &'a str) -> Self {
        AdditionStringModifier::new(s, 0)
    }
}

impl<'a> StringModificator<'a> for RandomChangeStringModifier {
    fn modify(&mut self) -> String {
        let mut changable_str = self.data.clone().into_bytes();
        let mut rng = thread_rng();
        let random_pos:usize = rng.gen_range(0..self.data.len());
        loop {
            let random_change:u8 = rng.gen_range(0..128); // because we want ascii in utf8
            if random_change != changable_str[random_pos as usize] {
                changable_str[random_pos as usize] = random_change;
                break;
            }
        }
        match String::from_utf8(changable_str) {
            Ok(val) => {
                self.data = val.clone();
                val
            },
            _ => String::new()
        }
    }
    
    fn from_str(s: &'a str) -> Self {
        RandomChangeStringModifier::new(s)
    }
}

impl AttackResult {
    fn to_string(&self) -> String {
        format!("Iterations Count: {0}
        Founded collision: ({1}, {2})
        Hash1: {3}
        Hash2: {4}", self.iterations_count, self.collision.0, self.collision.1, hash(&self.collision.0), hash(&self.collision.1))
    }
}

// TODO: it could be faster if we replaced iter()
// Maybe even faster is to make it using format!) But ok, let it be)
// TODO: Maybe i should make benchmarks on previous point
fn byte_as_str(byte: u8) -> String {
    let mut res_string = String::new();
    let half_byte = [(byte & 240) >> 4, byte & 15];
    for &i in half_byte.iter() {
        match i {
            00 => res_string.push('0'),
            01 => res_string.push('1'),
            02 => res_string.push('2'),
            03 => res_string.push('3'),
            04 => res_string.push('4'),
            05 => res_string.push('5'),
            06 => res_string.push('6'),
            07 => res_string.push('7'),
            08 => res_string.push('8'),
            09 => res_string.push('9'),
            10 => res_string.push('a'),
            11 => res_string.push('b'),
            12 => res_string.push('c'),
            13 => res_string.push('d'),
            14 => res_string.push('e'),
            15 => res_string.push('f'),
            _ => unreachable!("This arm is unreacheble")
        }
    }
    res_string
}

fn byte_arr_as_str(arr: &[u8]) -> String {
    let mut res_str = String::new();
    for &c in arr.iter() {
        res_str.push_str(&byte_as_str(c));
    }
    res_str
}
fn hash<'a>(s: &'a str) -> String {
    let mut hasher = Sha3_224::new();
    hasher.update(s.as_bytes());
    let res: [u8; 28] = hasher.finalize().into();
    byte_arr_as_str(&res)
}


fn second_preimage_attack<'a, T>(s: &'a str) -> AttackResult
where
T: StringModificator<'a>
{
    let hashed_value = hash(s);
    let mut modifier: T = T::from_str(s);
    let mut iter_count: u64 = 0;
    loop {
        iter_count += 1;
        let modified_value = modifier.modify();
        let hashed_modified_value = hash(&modified_value);
        // if iter_count <= 30 {println!("{:?}", modified_value)};
        if &hashed_value[hashed_value.len() - 4..] == &hashed_modified_value[hashed_modified_value.len() - 4..] {
            return AttackResult {
                iterations_count: iter_count,
                collision : (s.to_owned(), modified_value)
            };
        }
    }
}

fn birthday_attack<'a, T>(s: &'a str) -> AttackResult
where
T : StringModificator<'a>
{
    let mut hash_set = HashMap::<String, String>::new();
    let mut modifier: T = T::from_str(s);
    let mut iter_count: u64 = 0;
    loop {
        iter_count += 1;
        let val = modifier.modify();
        let hash_val = hash(&val);
        let hash_val = &hash_val[hash_val.len() - 8..];
        // if iter_count <= 30 {println!("{:?}", val)};
        if let Some(finded) = hash_set.get(hash_val) {
            if finded == &val { continue; }
            return AttackResult {
                iterations_count: iter_count,
                collision: (val, finded.to_owned())
            };
        } else {
            hash_set.insert(hash_val.to_owned(), val);
        }
    }
}

fn test_random_changes(hash_input: &str) {
    let mut modifier = RandomChangeStringModifier::new(&hash_input);
    let mut hash_map = HashMap::<usize, u64>::new();
    let n = hash_input.len() * 100;
    let mut rng = rand::thread_rng();
    for _ in 0..n {
        let temp = rng.gen_range(0..hash_input.len());
        //let temp = random::<usize>() % hash_input.len();
        if let Some(val) = hash_map.get_mut(&temp) {
            *val += 1;
        } else {
            hash_map.insert(temp, 0);
        }
    }

    for (k, v) in hash_map.iter() {
        println!("{0} : {1}", k, v);
    }
}

fn gen_initial_message() -> String {
    let mut res = String::from("IsachenkoNikitaSergiyovich");
    let random_number = random::<u16>();
    res.push_str(&random_number.to_string());
    res
}

fn test_attack<F : Fn(&str) -> AttackResult>(attack_function: F, n: u32, output_file: &str) {
    let file = File::create(output_file);
    if file.is_err() {
        panic!("output_file is incorrect!");
    }

    let file = file.unwrap();
    //let mut writer = BufWriter::new(&file);
    let mut  csv_writer = csv::WriterBuilder::new()
        .delimiter(b';')
        .from_writer(&file);
    _ = csv_writer.write_record(&["N", "Initial_Message", "Message_Hash", "Collision_1", "Collision_2", "Hash_1", "Hash_2", "Iterations", "Time elapsed"]);
    for i in 1..=n {
        println!("Attack {i}/{n}:");
        let initial_message = gen_initial_message();
        let message_hash: String = hash(&initial_message);
        let timer = Instant::now();
        let res = attack_function(&initial_message);
        let timer = timer.elapsed();
        // _ = writeln!(writer, 
        // "N_{i}\n
        // message_hash: {message_hash}
        // {0}
        // Elapsed time: {1} ms.\n\n", res.to_string(), timer.as_millis());
        let hash1 = hash(&res.collision.0);
        let hash2 = hash(&res.collision.1);
        _ = csv_writer.write_record(&[&i.to_string(), initial_message.as_str(), &message_hash, &res.collision.0, &res.collision.1, &hash1, &hash2, &res.iterations_count.to_string(), &timer.as_millis().to_string()]);
    }
}

fn app() {
    let args: Vec<_> = std::env::args().collect();
    let n = if args.len() < 2 {
        1
    } else {
        if let Ok(val) = args[1].parse::<u32>() {
            val
        } else {
            panic!("Arg must be a num")
        }
    };

    let filename = if args.len() < 3 {
        ""
    } else {
        args[2].as_str()
    };

    println!("Second preimage attack(addition):");
    test_attack(
        |s: &str| -> AttackResult {
        second_preimage_attack::<AdditionStringModifier>(s)
    }, n, &format!("{filename}_{0}", "second_preimage_addition_stategy.csv"));
    println!("\nSecond preimage attack(randchange):");
    test_attack(
        |s: &str| -> AttackResult {
        second_preimage_attack::<RandomChangeStringModifier>(s)
    }, n, &format!("{filename}_{0}","second_preimage_randchange_stategy.csv"));
    
    println!("\nBirthday attack(addition):");
    test_attack(
        |s: &str| -> AttackResult {
        birthday_attack::<AdditionStringModifier>(s)
    }, n, &format!("{filename}_{0}","birthday_addition_stategy.csv"));
    println!("\nBirthday attack(randchange):");
    test_attack(
        |s: &str| -> AttackResult {
        birthday_attack::<RandomChangeStringModifier>(s)
    }, n, &format!("{filename}_{0}","birthday_randchange_stategy.csv"));
}

// TODO: add comand line args parser
fn main() {
    app();
    // let message = gen_initial_message();
    // let res: AttackResult = second_preimage_attack::<RandomChangeStringModifier>(&message);
    // let hash1 = hash(&res.collision.0);
    // let hash2 = hash(&res.collision.1);
    // println!("Initial message: {message}");
    // println!("{:?}", res);
    // println!("Hash1: {hash1},\nHash2: {hash2}");
}
