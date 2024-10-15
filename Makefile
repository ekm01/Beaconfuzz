beaconfuzz: main.py
	echo '#!/bin/bash\npython3 $< "$${@:1}"' > $@
	chmod +x $@

clean:
	rm -f beaconfuzz
