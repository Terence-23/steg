use clap::{Parser, ValueEnum};
use std::io::{BufReader, Read, Write};
use std::{fs::File, io::BufWriter, path::PathBuf};

use crate::steg::{LeastBit, StegData, Steganography};

mod steg;

#[derive(clap::Parser)]
#[command(version, about, long_about=None)]
struct Config {
    #[command(subcommand)]
    command: Command,
    #[arg(value_enum)]
    method: StegMethod,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum StegMethod {
    /// least bit of each pixxel channel contains the data. Not robust against lossy encoding
    LeastBit,
}

#[derive(clap::Subcommand)]
enum Command {
    /// encode provided data into the image
    Encode {
        /// image to be altered
        #[arg(long, short, value_name = "FILE")]
        image: PathBuf,
        /// optional, path to the output image otherwise overwrites source image
        #[arg(long, short, value_name = "FILE")]
        output_image: Option<PathBuf>,
        /// file containing data to be encoded
        #[arg(long, short, value_name = "FILE")]
        data: PathBuf,
    },
    Decode {
        /// image containing the data
        #[arg(long, short, value_name = "FILE")]
        image: PathBuf,

        /// optional, if given outputs to the file, otherwise to stdout
        #[arg(long, short)]
        output: Option<PathBuf>,
    },
}

fn steg_with_method(method: impl Steganography<u8>, command: Command) -> anyhow::Result<()> {
    match command {
        Command::Encode {
            image,
            output_image,
            data,
        } => {
            let mut img = image::open(image.clone())?.to_rgb8();
            let mut buf = vec![];
            BufReader::new(File::open(data)?).read_to_end(&mut buf)?;

            let data = StegData::new(&buf);
            method.encode(&data, &mut img)?;

            let output = match output_image {
                Some(s) => s,
                None => image,
            };

            img.save(output)?;
        }
        Command::Decode { image, output } => {
            let img = image::open(image)?.to_rgb8();
            let data = method.decode(&img)?;
            if let Some(f) = output {
                let mut writer = BufWriter::new(File::create(f)?);
                writer.write(data.get_data())?;
            } else {
                let mut writer = BufWriter::new(std::io::stdout());
                writer.write(data.get_data())?;
            };
        }
    }
    return Ok(());
}
fn main() -> anyhow::Result<()> {
    let args = Config::parse();
    steg_with_method(
        match args.method {
            StegMethod::LeastBit => LeastBit {},
        },
        args.command,
    )
}
