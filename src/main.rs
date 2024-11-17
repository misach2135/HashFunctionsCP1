use core::fmt;
use std::{borrow::Cow, cell::Cell, collections::{hash_map, HashMap, HashSet}, ops::Add};
use rand::{random, rngs::ThreadRng, thread_rng, Rng};

use sha3::{Digest, Sha3_224};

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
    fn modifyDebug(&self) -> (String, usize) {
        let mut changable_str = self.data.clone().into_bytes();
        let random_pos:usize = random::<usize>() % self.data.len();
        let random_change:u8 = random::<u8>() & 127; // because we want ascii in utf8
        changable_str[random_pos as usize] = random_change;
        match String::from_utf8(changable_str) {
            Ok(val) => (val, random_pos),
            _ => (String::new(), random_pos)
        }
    }
    
    fn modify(&mut self) -> String {
        let mut changable_str = self.data.clone().into_bytes();
        let random_pos:usize = random::<usize>() % self.data.len();
        let random_change:u8 = random::<u8>() & 127; // because we want ascii in utf8
        changable_str[random_pos as usize] = (random_change + changable_str[random_pos as usize]) & 127;
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


fn second_preimage_attack<'a, T>(s: &'a str) -> (String, String)
where
T: StringModificator<'a>
{
    let hashed_value = hash(s);
    let mut modifier: T = T::from_str(s);
    loop {
        let modified_value = modifier.modify();
        let hashed_modified_value = hash(&modified_value);
        // println!("modified_value: {:?}", modified_value);
        if &hashed_value[hashed_value.len() - 4..] == &hashed_modified_value[hashed_modified_value.len() - 4..] {
            return (s.to_owned(), modified_value);
        }
    }
}

fn birthday_attack<'a, T>(s: &'a str) -> (String, String) 
where
T : StringModificator<'a>
{
    let mut hash_set = HashMap::<String, String>::new();
    let mut modifier: T = T::from_str(s);

    loop {
        let val = modifier.modify();
        let hash_val = hash(&val);
        let hash_val = &hash_val[hash_val.len() - 8..];
        if let Some(finded) = hash_set.get(hash_val) {
            let finded = finded.to_owned();
            if finded == val {
                continue;
            }
            return (val, finded);
        } else {
            hash_set.insert(hash_val.to_owned(), val);
        }
    }
}

fn test_random_changes(hash_input: &str) {
    let modifier = RandomChangeStringModifier::new(&hash_input);
    let mut hash_map = HashMap::<usize, usize>::new();
    
    let n = 260_000;

    for _ in 0..n {
        let modify_res = modifier.modifyDebug();
        if let Some(val) = hash_map.get_mut(&modify_res.1) {
            *val += 1;
        } else {
            hash_map.insert(modify_res.1, 1);
        }
    }

    for pair in hash_map.iter() {
        let stat = 1.0 - (*pair.1 as f64) / ((n as f64) / 26.0);
        println!("{:?}: {1}", pair.0, stat);
    }

    println!("{:?}", hash_map.len());
    println!("{:?}", hash_map);
}

fn gen_initial_message() {
    todo!()
}

fn main() {
    let hash_input = "NikitaIsachenkoSergiyovich";
    let hash_val = hash("NikitaIsachenkoSergiyovich");
    println!("Hash: {:?}", hash_val);
    println!("Len: {:?}", "NikitaIsachenkoSergiyovich".len());

    // println!("Addition Modifications strategy: ");
    // let res= second_preimage_attack::<AdditionStringModifier>(&hash_input);
    // println!("{:?}", res);
    // println!("Changing Modifications strategy: ");
    // let res= second_preimage_attack::<RandomChangeStringModifier>(&hash_input);
    // println!("{:?}", res);

    println!("Addition Modifications strategy: ");
    // let res= birthday_attack::<AdditionStringModifier>(&hash_input);
    //println!("{:?}", res);
    println!("Changing Modifications strategy: ");
    let res= birthday_attack::<RandomChangeStringModifier>(&hash_input);
    println!("{:?}", res);
}
