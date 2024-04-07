# iquic_learner
It's project denoted for "localhost" aioquic learner tool 
## run_server
python3 examples/http3_server.py --certificate tests/ssl_cert.pem --private-key tests/ssl_key.pem -l keylog

 
Installing
----------

The easiest way to install ``aioquic`` is to run:

.. code:: bash

    pip install aioquic

Building from source
--------------------

If there are no wheels for your system or if you wish to build ``aioquic``
from source you will need the OpenSSL development headers.

Linux
--------------------

On Debian/Ubuntu run:

.. code-block:: console

   sudo apt install libssl-dev python3-dev
