# Deserialization (CWE-502: unsafe object reconstruction)

## What it is

Serialization converts an object into bytes; deserialization converts bytes back
into an object. The dangerous kind of deserialization does more: it *executes*.
A format that can describe arbitrary objects and a loader that can instantiate
them turn a data channel into a code channel, and the attacker supplies the data.

The trust boundary crossed is between "bytes are data" and "bytes are
instructions". Crossing it requires nothing but a well-formed payload reaching the
loader.

## Detection

### The dangerous loaders

| Look for | Why it is dangerous |
| --- | --- |
| `pickle.loads(`, `pickle.load(`, `cPickle` | Instantiates arbitrary classes; `__reduce__` runs any callable |
| `yaml.load(` without `Loader=` | Same class of problem; `yaml.load(data)` is unsafe |
| `yaml.load(data, Loader=yaml.Loader)` / `yaml.UnsafeLoader` | Explicitly unsafe |
| `marshal.loads(` | Not designed for untrusted input |
| `shelve.open(` on data from a request | Pickle underneath |
| `dill.loads(` | Pickle-family, same problem |
| `jsonpickle.decode(` | Can reconstruct objects |
| `torch.load(` without `weights_only=True` | Executes arbitrary pickle opcodes |
| `numpy.load(` with `allow_pickle=True` | Pickle opt-in |
| `Java` `ObjectInputStream.readObject()` | Gadget chains (`CommonsCollections`, ...) |
| `PHP` `unserialize(` on request data | Object injection |
| `Ruby` `Marshal.load(` on request data | Same |
| `.NET` `BinaryFormatter.Deserialize(` | Unsafe by design, deprecated |

The registry carries `pickle-load-sink` and `yaml-load-sink` as
deserialization sinks, with `yaml-safe-load` and `json-loads-safe` as the
sanitizers that break the flow. A path from an HTTP source, a file-read source,
or a message-queue source into one of those sinks is a finding.

### The indirect shape

The loader is often not in the file you are reading. Look for a session or cache
backend configured with pickle, a Celery/RQ task serializer set to `pickle`, a
Flask `session` cookie, or a `redis.set(key, pickle.dumps(obj))` /
`pickle.loads(redis.get(key))` pair. The sink and the source can be separated by
the entire request cycle.

## How it works (attack mechanics)

`pickle` is a small stack-based virtual machine. Its `REDUCE` opcode calls an
arbitrary callable with arbitrary arguments. A pickle payload can therefore be a
program:

    cos\nsystem\n(S'<command>'\ntR.

which, when loaded, calls `os.system("<command>")`. There is no parser bug and no
bypass -- this is the documented purpose of the opcode. The payload is a *shape*
against a local fixture; it demonstrates that the loader executes rather than
parses, and nothing more should be inferred about any real product.

The same reasoning applies to `yaml.load` with the unsafe loader (Python object
tags such as `!!python/object/apply:`) and to `.NET` `BinaryFormatter` (a gadget
chain reaching a dangerous call). Java `readObject` is reached by chaining
classes already on the classpath into a call, which is why the fix is to not
deserialize untrusted data at all rather than to look for a bad gadget.

## Is it actually exploitable?

1. **Does the data reach the loader from outside the trust boundary?** A pickle
   written and read by the same process over data the process itself created is
   not a vulnerability. A pickle in a session cookie, a queue message, an
   uploaded file, or a cache another service writes is.
2. **Is the loader in production code?** In `tests/`, a fixture round-trip is
   normal and expected.
3. **Is there a signature check before the load?** An HMAC over the blob, verified
   with a constant-time comparison before deserializing, does close the boundary
   -- but only if the key is not also in the source (see
   `skills/13-secrets-and-tokens.md`).
4. **Can the format carry objects at all?** JSON, MessagePack, and protocol
   buffers without `Any` fields carry data only. Switching to one of them is the
   fix, not a workaround.

## False positives (do NOT report)

- **A pickle written and read inside one process**, over data that process
  created, with no external writer. A cache, a memo, an IPC between your own
  workers with a shared secret.
- **Test fixtures.** `pickle.dumps` in a fixture and `pickle.loads` in a test.
- **`pickle.loads` over a signature-verified blob.** Verify the verification is
  real (correct key, constant-time compare, verified *before* the load, not
  after), then file it as audited.
- **`json.loads`.** Data-only. Not this class.
- **`yaml.safe_load`.** Safe by construction; the sanitizer is applied.
- **A `.pkl` asset in a model directory loaded at startup** with no external
  writer. Note it with the trust assumption stated.

Reporting an internal pickle round-trip as remote code execution is the most
overstated claim in this class, and the maintainer's one-line reply -- "nothing
outside the process writes that" -- discredits the rest of the report.

## Severity

Untrusted data reaching a pickling loader is arbitrary code execution as the
application's own user:

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
https://www.first.org/cvss/calculator/4.0#CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N
```

`AC:L` because there is no mechanism to evade -- the loader's behaviour is the
mechanism, and it is doing exactly what it is designed to do. If the payload must
first land in a specific cache entry or be wrapped by a specific envelope, that
is a prerequisite and moves `AT:N` to `AT:P`. Where the affected process is a
worker with no network listener, `AV` is not `N` -- it is whatever the attacker
used to deliver the blob, often `A` or `L`. Do not default to worst case. Never
hand-compute the number.

## Remediation

    # before                                # after
    data = pickle.loads(blob)               data = json.loads(blob)
    conf = yaml.load(text)                  conf = yaml.safe_load(text)
    m = torch.load(path)                    m = torch.load(path, weights_only=True)
    arr = np.load(p)                        arr = np.load(p, allow_pickle=False)

Where the object graph is genuinely needed, do not deserialize it from untrusted
bytes. Options, in order of preference:

1. **Change the format to a data-only one** (JSON, MessagePack, protobuf without
   `Any`) and validate against a schema. Reconstruct the object from validated
   fields.
2. **Sign the blob and verify before loading.** HMAC with a key from the
   environment; verify, then deserialize. Note that this makes the deserializer a
   trusted-consumer, so the signing key's secrecy is load-bearing.
3. **Restrict the loader.** `yaml.safe_load`, `torch.load(weights_only=True)`,
   `numpy.load(allow_pickle=False)`, and on .NET avoid `BinaryFormatter`
   entirely (it has no safe configuration and is deprecated).

For a queue/cache backend, change the serializer in the worker configuration --
one line, and it fixes every handler.

## Verify the fix

- `grep -rn 'pickle.loads\|pickle.load\|yaml.load\|marshal.loads' --include='*.py' .`
  excluding tests returns nothing.
- A test that sends the pickle shape above to the affected entry point and asserts
  the command did not execute -- either a mock asserting the callable was never
  invoked, or a marker file asserted absent.
- A test asserting an unsafe YAML tag (`!!python/object/apply:`) is rejected.
- If the fix was a format change, a test that the new format cannot express an
  object: attempting to embed a Python object tag fails at parse time.
