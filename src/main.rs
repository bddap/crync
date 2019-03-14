use structopt::StructOpt;
mod encoding;
mod opt;
mod run;

fn main() {
    opt::Opt::from_args().run();
}
