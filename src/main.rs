/**
 * Copyright (C) 2021 KeyboardSlayer (Jordan Dalcq)
 * 
 * This file is part of Runas.
 * 
 * Runas is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * Runas is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with Runas.  If not, see <http://www.gnu.org/licenses/>.
 */

use std::env;
use std::fs;
use std::path::Path;
use std::ffi::CString;
use std::process::exit;

use yaml_rust::{YamlLoader, yaml::Yaml};
use pwhash::{sha512_crypt, sha256_crypt, md5_crypt};
use libc::{setuid, system};
use users::get_current_username;
use rpassword;

fn get_uid(username: String) -> u32 
{
    let lines = fs::read_to_string("/etc/passwd").unwrap();
    let passwd: Vec<&str> = lines.split("\n").collect();

    if let Some(line) = passwd.iter().filter(|x| x.get(0..username.len()).unwrap() == username).next()
    {
        return line.split(":").collect::<Vec<&str>>()[3].parse::<u32>().unwrap();
    }
    else 
    {
        eprintln!("Unknown user {} !", username);
        exit(1);
    }
}

fn check_password(username: String) -> bool
{
    let pass = rpassword::prompt_password_stdout("Password: ").unwrap();

    match fs::read_to_string("/etc/shadow")
    {
        Ok(conf) => {
            let shadow: Vec<&str> = conf.split("\n").collect();

            if let Some(line) = shadow.iter().filter(|x| x.get(0..username.len()).unwrap() == username).next()
            {
                let fields: Vec<&str> = line.split(":").collect::<Vec<&str>>()[1].split("$").collect();
                let h = format!("${}${}", fields[1], fields[2]);

                match fields[1] 
                {
                    "1" => {
                        #[allow(deprecated)]
                        return md5_crypt::hash_with(h.as_str(), pass).unwrap() == format!("${}${}${}", fields[1], fields[2], fields[3]);   
                    }

                    "5" => {
                        #[allow(deprecated)]
                        return sha256_crypt::hash_with(h.as_str(), pass).unwrap() == format!("${}${}${}", fields[1], fields[2], fields[3])

                    }

                    "6" => {
                        return sha512_crypt::hash_with(h.as_str(), pass).unwrap() == format!("${}${}${}", fields[1], fields[2], fields[3]);
                    }
                    _ => {
                        eprintln!("Encryption type ${}$ unknown, please report it on our Github", fields[1]);
                        exit(1);
                    }
                }

            }
            else 
            {
                eprintln!("STOP DOING BLACK MAGIC !");
                exit(1);
            }
        }

        Err(err) => {
            eprintln!("{:?}", err);
            exit(1);
        }
    }
}

fn load_config(filename: String) -> Vec<Yaml>
{
    let mut config: Vec<Yaml> = vec![];

    if let Ok(content) = fs::read_to_string(filename)
    {
        match YamlLoader::load_from_str(content.as_str())
        {
            Ok(conf) => {
                config = conf;
            }

            Err(p) => {
                eprintln!("{}", p);
                exit(1);
            }
        }
    }

    config
}

fn main()
{
    let mut args: Vec<String> = env::args().collect();
    
    let name = args.first().unwrap().clone();
    let usage = format!("usage: {} [-C config] [-u user] command [args]", name);
    
    let mut config = String::from("/etc/runas.yml");
    let mut user = String::from("root");
    let whoami = String::from(get_current_username().unwrap().to_str().unwrap());

    let mut cmd: String = String::from("false");
    let mut cmd_args: Vec<String> = vec![];
    let mut cmd_found = false;

    let mut logged = false;

    args.remove(0);
    
    if args.len() == 0
    {
        eprintln!("{}", usage);
        exit(1);
    }

    let mut iter = IntoIterator::into_iter(args);

    loop
    {
        if let Some(arg) = iter.next() 
        {
            if arg.get(0..1).unwrap() == "-"
            {
                match arg.as_str() 
                {
                    "-C" => {
                        if let Some(conf) = iter.next()
                        {
                            config = conf;
                        }
                        else 
                        {
                            eprintln!("{}: option requires an argument -- 'C'\n{}", name, usage);
                            exit(1);
                        }
                    }
    
                    "-u" => {
                        if let Some(usr) = iter.next()
                        {
                            user = usr;
                        }
                        else 
                        {
                            eprintln!("{}: option requires an argument -- 'u'\n{}", name, usage);
                            exit(1);
                        }
                    }
    
                    _ => {
                        eprintln!("{}: invalid option -- '{}'\n{}", name, arg.get(1..arg.len()).unwrap(), usage);
                        exit(1);
                    } 
                }
            }
            else 
            {
                cmd_args = iter.collect();
                cmd = arg;

                if let Ok(path) = env::var("PATH") 
                {
                    for path in path.split(":").collect::<Vec<&str>>() 
                    {
                        if Path::new(format!("{}/{}", path, cmd).as_str()).exists()
                        {
                            cmd_found = true;
                        }
                    }

                    if !cmd_found 
                    {
                        eprintln!("{}: {}: command not found", name, cmd);
                        exit(1);
                    }
                }
                break; 
            }
        }
        else 
        {
            break;
        }
    }

    if !cmd_found
    {
        eprintln!("{}: no command specified", name);
        exit(1);
    }

    let yml = load_config(config);

    if yml.len() == 0
    {
        eprintln!("{}: config file not found", name);
        exit(1);
    }

    let doc = &yml[0];


    if doc[whoami.as_str()].is_badvalue()
    {
        eprintln!("{}: Operation not permitted", name);
        exit(1);
    }

    if doc[whoami.as_str()]["ALL"].is_badvalue()
    {
        if doc[whoami.as_str()][user.as_str()].is_badvalue()
        {
            eprintln!("{}: Operation not permitted", name);
            exit(1);
        }
    }
    else 
    {
        user = String::from("ALL");
    }


    if let Some(line) = &doc[whoami.as_str()][user.as_str()].as_vec()
    {
        if line.iter().any(|x| x.as_str() != Some("ALL")) && line.iter().any(|y| y.as_str() != Some(cmd.as_str()))
        {
            eprintln!("{}: Operation not permitted", name);
            exit(1);
        }
    }
    else 
    {
        eprintln!("Parsing error !\n");
        exit(1);
    }

    if doc[whoami.as_str()]["nopass"].as_bool() == Some(false) || doc[whoami.as_str()]["nopass"].is_badvalue()
    {
        for i in 0..3 
        {
            if i > 0
            {
                eprintln!("Password incorrect !");
            }
    
            if check_password(whoami.clone()) == true 
            {
                logged = true;
                break;
            }
        }
    
        if !logged
        {
            eprintln!("Too many attempts !");
            exit(1);
        }
    }


    let joined = cmd_args.join(" ");
    let command: CString = CString::new(format!("{} {}", cmd, joined).as_str()).unwrap();


    unsafe 
    {
        setuid(get_uid(user));
        system(command.as_ptr());
    }
}