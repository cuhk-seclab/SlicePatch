# SlicePatch

SlicePatch is a prototype for Web application vulnerability repair via context-aware fault localization and directed differential fuzzing. 

## Installation

All dependencies are containerized via Docker.

```bash
cd docker && ./build-all.sh
```

## Usage

### Start Docker and enter the container

```bash
cd /path/to/SlicePatch

docker run -p 8080:80 -id --rm \
   --name slicepatch-demo \
   -w /test \
   -v $(pwd)/working:/p \
   -v $(pwd)/scripts:/test \
   witcher/directphp7run

docker exec -it -u wc slicepatch-demo bash
```

### Prepare the target application and required files

Before running SlicePatch, prepare the following items in the container:

- Install the target application under `/app/<target-app>`.
- Prepare an original version for differential testing as well, for example `/app/joomla` and `/app/joomla_ori`.
- Prepare `/test/witcher_config.json`. We provide an example at `/SlicePatch/configs/witcher_config.json.example`.
- Configure the LLM API key and URL in `scripts/utils.py`.
- Prepare the POC script under `scripts/poces/`.

### Run batch patching

As user `wc`, run the batch script from `/test`:

```bash
cd /test
./batch_patching.sh -a /app/joomla -p joomla
```

SlicePatch will automatically process all POC scripts in `scripts/poces/` whose filenames start with `joomla`.

### Run a single POC manually

```bash
cd /test
python3.8 ./start_patching_loop.py \
   -a /app/joomla \
   -w assembled \
   -o instrument-info \
   -p poces/joomla-2017-8917.py \
   -r
```

## Predator Configuration Reference

For more examples of `witcher_config.json`, `request_data.json`, and working-directory layout, please refer to [Predator](https://github.com/cuhk-seclab/Predator).

## Citation

If you use this repository, please cite the following paper:

```bibtex
@inproceedings{wang2026slicepatch,
   title={Web Application Vulnerability Repair via Context-Aware Fault Localization and Directed Differential Fuzzing},
   author={Wang, Chenlin and Meng, Wei},
   booktitle={2026 IEEE Symposium on Security and Privacy (SP)},
   year={2026},
   organization={IEEE Computer Society}
}
```

## Contact

Chenlin Wang (clwang23@cse.cuhk.edu.hk)