#########################################################################################
FROM witcher/directbaserun as directphp7run
##################################################################################################################################

# Install dependencies
RUN apt-get update \
    && apt-get install -y \
        wget build-essential libxml2-dev libssl-dev libcurl4-openssl-dev libjpeg-dev \
        libpng-dev libfreetype6-dev libzip-dev libonig-dev libmcrypt-dev libsqlite3-dev \
        perl git unzip autoconf fonts-dejavu java-common libasound2 libfontconfig1 libxi6 \
        libxrender1 libxtst6 python3-pip graphviz libgraphviz-dev vim \
        libgmp-dev libgmp3-dev

RUN mkdir -p /usr/local/php7.0/etc/ \
    && mkdir -p /usr/local/php7.4/etc/

# Download and install PHP 7.0 from source
RUN mkdir -p /usr/src/php7.0 \
    && cd /usr/src/php7.0 \
    && wget https://www.php.net/distributions/php-7.0.33.tar.gz \
    && tar -xzvf php-7.0.33.tar.gz \
    && cd php-7.0.33 \
    && ./configure \
        --prefix=/usr/local/php7.0 \
        --with-config-file-path=/usr/local/php7.0/etc \
 		\
		--enable-cgi      \
		--enable-ftp      \
		--enable-mbstring \
		--enable-sockets  \
		--enable-gettext  \
		--with-gd         \
		--with-gmp        \
		\
		--with-mysql      \
		--with-openssl      \
		--with-mysqli      \
		--with-pdo-mysql  \
		--with-zlib       \
    && make \
    && make install

# Set environment variables for PHP 7.0
ENV PATH="/usr/local/php7.0/bin:${PATH}"
ENV PHP_INI_DIR="/usr/local/php7.0/etc"

#+ install static analysis environment and tools +
RUN mkdir /static-tools && cd /static-tools &&\
    git clone https://github.com/nikic/php-ast.git &&\
    cd php-ast &&\
    git checkout 701e853 &&\
    phpize &&\
    ./configure &&\
    make && make install


COPY --from=witcher/directphp7build /usr/local/bin/php /usr/local/bin/php-config /usr/local/bin/phpize /usr/local/bin/php-cgi /usr/local/bin/phar.phar /usr/local/bin/phpdbg /usr/local/bin/
COPY --from=witcher/directphp7build /usr/local/lib/php/build/ /usr/local/lib/php/build/
COPY --from=witcher/directphp7build /usr/lib/apache2/modules/libphp7.so /usr/lib/apache2/modules/libphp7.so
COPY --from=witcher/directphp7build /usr/local/include/php/ /usr/local/include/php/
COPY --from=witcher/directphp7build /usr/local/bin/ /usr/local/bin/
# for zip curl gd ... extensions
COPY --from=witcher/directphp7build /phpsrc/ext /phpext

# Set environment variables for PHP 7.4
ENV PATH="/usr/local/bin:${PATH}"
ENV PHP_INI_DIR="/usr/local/lib" 

#+ temp add opcache
#COPY --from=witcher/directphp7build /phpsrc/ext/opcache /opcache

######### apache, php, and crawler setup
RUN apt-fast install -y libpng16-16 net-tools ca-certificates fonts-liberation libappindicator3-1 libasound2 \
                        libatk-bridge2.0-0 libatk1.0-0  libc6 libcairo2 libcups2 libdbus-1-3  libexpat1 libfontconfig1 \
                        libgbm1 libgcc1 libglib2.0-0 libgtk-3-0  libnspr4 libnss3 libpango-1.0-0 libpangocairo-1.0-0 \
                        libstdc++6 libx11-6 libx11-xcb1 libxcb1 libxcomposite1 libxcursor1 libxdamage1 libxext6 libxfixes3 \
                        libxi6 libxrandr2 libxrender1 libxss1 libxtst6 lsb-release wget xdg-utils \
                        unzip graphviz libgraphviz-dev chromium-chromedriver sqlite \
                        libcurl4-openssl-dev libpng-dev libzip-dev pkg-config libicu-dev \
                        php-xdebug 
                        # php-opcache
                       
RUN php -i
RUN cd /static-tools/php-ast &&\
    git checkout tags/v1.1.1 &&\
    phpize &&\
    ./configure &&\
    make && make install

# Add the extension configuration to php.ini
RUN echo 'extension=ast.so' | tee -a /usr/local/php7.0/etc/php.ini && \
    echo 'extension=ast.so' | tee -a /usr/local/lib/php.ini && \
    echo 'memory_limit = -1' | tee -a /usr/local/php7.0/etc/php.ini && \
    echo 'memory_limit = -1' | tee -a /usr/local/lib/php.ini

# install php-cs-fixer
RUN cd /static-tools &&\
    wget https://cs.symfony.com/download/php-cs-fixer-v3.phar -O php-cs-fixer &&\
    chmod +x php-cs-fixer

# install phpjeorn
RUN cd /static-tools &&\
    git clone https://github.com/1TreeForest/phpjoern.git
# Install OpenJDK 1.8
RUN cd /static-tools &&\
    wget https://builds.openlogic.com/downloadJDK/openlogic-openjdk/8u392-b08/openlogic-openjdk-8u392-b08-linux-x64-deb.deb &&\
    apt install -y ./openlogic-openjdk-8u392-b08-linux-x64-deb.deb &&\
    rm openlogic-openjdk-8u392-b08-linux-x64-deb.deb
#+ install gradle2
RUN cd /static-tools &&\
    wget https://services.gradle.org/distributions/gradle-2.1-bin.zip &&\
    unzip -d /opt/gradle gradle-2.1-bin.zip &&\
    ln -s /opt/gradle/gradle-2.1/bin/gradle /usr/bin/gradle &&\
    rm gradle-2.1-bin.zip
#+ install oldjoern
RUN cd /static-tools &&\
    git clone https://github.com/1TreeForest/joern.git &&\
    pip3 install pygraphviz==1.5 &&\
    ls -l &&\
    mv joern oldjoern &&\
    cd oldjoern &&\
    gradle build -x test

RUN chmod 777 /static-tools/* && chmod 777 /static-tools && chmod 777 /test && chmod 777 /tmp

ENV APACHE_RUN_DIR=/etc/apache2/

# + temp add
COPY etc/apache2.conf /etc/apache2/apache2.conf

RUN echo "ServerName localhost" >> /etc/apache2/apache2.conf
# RUN ln -s /etc/php/7.1/mods-available/mcrypt.ini /etc/php/7.3/mods-available/ && phpenmod mcrypt

RUN sed -i "s/.*bind-address.*/bind-address = 0.0.0.0/" /etc/mysql/my.cnf \
  && sed -i "s/.*bind-address.*/bind-address = 0.0.0.0/" /etc/mysql/mysql.conf.d/mysqld.cnf

# change apache to forking instead of thread
RUN rm -f /etc/apache2/mods-enabled/mpm_event.* \
    && rm -f /etc/apache2/mods-enabled/mpm_prefork.* \
    && ln -s /etc/apache2/mods-available/mpm_prefork.load /etc/apache2/mods-enabled/mpm_prefork.load \
    && ln -s /etc/apache2/mods-available/mpm_prefork.conf /etc/apache2/mods-enabled/mpm_prefork.conf

COPY config/supervisord.conf /etc/supervisord.conf
COPY config/php.ini /usr/local/lib/php.ini
COPY config/php.ini /etc/php/7.2/apache2/php.ini
COPY config/php7.conf config/php7.load /etc/apache2/mods-available/

RUN ln -s /etc/apache2/mods-available/php7.load /etc/apache2/mods-enabled/ && ln -s /etc/apache2/mods-available/php7.conf /etc/apache2/mods-enabled/ && rm /usr/bin/php && ln -s /usr/local/bin/php /usr/bin/php

RUN a2enmod rewrite
ENV PHP_UPLOAD_MAX_FILESIZE 10M
ENV PHP_POST_MAX_SIZE 10M
RUN rm -fr /var/www/html && ln -s /app /var/www/html

#### XDEBUG #+ temp disable
RUN cd /phpext/xdebug && phpize && ./configure --enable-xdebug && make -j $(nproc) && make install

#### for ZIP gd curl gettext extension
RUN cd /phpext/zip && phpize && ./configure --with-php-config=/usr/local/bin/php-config && make -j $(nproc) && make install \
  && cd /phpext/gd && phpize && ./configure --with-php-config=/usr/local/bin/php-config && make -j $(nproc) && make install \
  && cd /phpext/curl && phpize && ./configure --with-php-config=/usr/local/bin/php-config && make -j $(nproc) && make install \
  && cd /phpext/intl && phpize && ./configure --with-php-config=/usr/local/bin/php-config && make -j $(nproc) && make install \
  && cd /phpext/gettext && phpize && ./configure --with-php-config=/usr/local/bin/php-config && make -j $(nproc) && make install

COPY --chown=wc:wc  config/phpinfo_test.php config/db_test.php config/cmd_test.php config/run_segfault_test.sh /app/

# disable directory browsing in apache2
RUN sed -i 's/Indexes//g' /etc/apache2/apache2.conf && \
    echo "DirectoryIndex index.php index.phtml index.html index.htm" >> /etc/apache2/apache2.conf

# add index
COPY config/000-default.conf /etc/apache2/sites-available/

#+ temp disable xdebug +
RUN mkdir /tmp/xdebug && mkdir /dev/shm/traces && mkdir /dev/shm/coverages && mkdir /tmp/webgrindStorage && chmod 777 /tmp/* && chmod 777 /app
RUN cd /var/www/html && git clone https://github.com/1TreeForest/webgrind.git
# RUN printf '\nzend_extension=/usr/local/lib/php/extensions/no-debug-non-zts-20190902/xdebug.so\nxdebug.mode=profile\nxdebug.profiler_enable = 1\nxdebug.profiler_append = 1\n\n' >> $(php -i |egrep "Loaded Configuration File.*php.ini"|cut -d ">" -f2|cut -d " " -f2)
# RUN for fn in $(find /etc/php/ . -name 'php.ini'); do printf '\nzend_extension=/usr/local/lib/php/extensions/no-debug-non-zts-20190902/xdebug.so\nxdebug.mode=profile\nxdebug.profiler_enable = 1\nxdebug.profiler_append = 1\n\n' >> $fn; done
RUN echo -e '\nzend_extension=/usr/local/lib/php/extensions/no-debug-non-zts-20190902/xdebug.so\nextension=ast.so\nmemory_limit=-1\nxdebug.mode=trace,coverage\nxdebug.start_with_request=trigger\nxdebug.trigger_value=1\nxdebug.output_dir=/dev/shm/traces\nxdebug.trace_options=1\nxdebug.trace_format=1\nxdebug.trace_output_name="trace.%p.%t"\nauto_prepend_file=/enable_cc.php\n\n' >> $(php -i |egrep "Loaded Configuration File.*php.ini"|cut -d ">" -f2|cut -d " " -f2)
RUN for fn in $(find /etc/php/ . -name 'php.ini'); do echo -e '\nzend_extension=/usr/local/lib/php/extensions/no-debug-non-zts-20190902/xdebug.so\nextension=ast.so\nmemory_limit=-1\nxdebug.mode=trace,coverage\nxdebug.start_with_request=trigger\nxdebug.trigger_value=1\nxdebug.output_dir=/dev/shm/traces\nxdebug.trace_options=1\nxdebug.trace_format=1\nxdebug.trace_output_name="trace.%p.%t"\nauto_prepend_file=/enable_cc.php\n\n' >> $fn; done

#+ zip curl gd gettext +
RUN printf '\nextension=zip\n' >> $(php -i |egrep "Loaded Configuration File.*php.ini"|cut -d ">" -f2|cut -d " " -f2) \
  # && printf '\nextension=curl\n' >> $(php -i |egrep "Loaded Configuration File.*php.ini"|cut -d ">" -f2|cut -d " " -f2) \
  && printf '\nextension=gd\n\n' >> $(php -i |egrep "Loaded Configuration File.*php.ini"|cut -d ">" -f2|cut -d " " -f2) \
  && printf '\nextension=intl\n\n' >> $(php -i |egrep "Loaded Configuration File.*php.ini"|cut -d ">" -f2|cut -d " " -f2) \
  && printf '\nextension=gettext\n\n' >> $(php -i |egrep "Loaded Configuration File.*php.ini"|cut -d ">" -f2|cut -d " " -f2) 

#+ temp add opcache +
#RUN printf '\nzend_extension=opcache.so\nopcache.enable=1\nopcache.enable_cli=1\nopcache.optimization_level=0\nopcache.opt_debug_level=0x10000\n\n' >> $(php -i |egrep "Loaded Configuration File.*php.ini"|cut -d ">" -f2|cut -d " " -f2)
#RUN for fn in $(find /etc/php/ . -name 'php.ini'); do printf '\nzend_extension=opcache.so\nopcache.enable=1\nopcache.enable_cli=1\nopcache.optimization_level=0\nopcache.opt_debug_level=0x10000\n\n' >> $fn; done

RUN echo 'alias p="python3.6 -m witcher --affinity $(( $(ifconfig |egrep -oh "inet 172[\.0-9]+"|cut -d "." -f4) * 2 ))"' >> /home/wc/.bashrc
COPY config/py_aff.alias /root/py_aff.alias
RUN cat /root/py_aff.alias >> /home/wc/.bashrc

# RUN cp /bin/dash /bin/saved_dash && cp /crashing_dash /bin/dash
RUN cp /usr/bin/python3 /usr/bin/python
# there's a problem with building xdebug and the modifid dash, so copy after xdebug
COPY --from=witcher/directbasebuild /Widash/archbuilds/dash /bin/dash

COPY --chown=wc:wc  config/codecov_conversion.py config/enable_cc.php /
# Enable sanbox
RUN sysctl -w kernel.unprivileged_userns_clone=1

RUN cd /tmp && update-alternatives --install /usr/bin/php php /usr/local/bin/php 100 \
  && php -r "copy('https://getcomposer.org/installer', 'composer-setup.php');" \
  && php composer-setup.php && mv composer.phar /usr/local/bin/composer

CMD /usr/bin/supervisord -c /etc/supervisord.conf

# env for slicePatch
# update python3.6 to python3.8
RUN sudo apt update && sudo apt install software-properties-common -y \
  && sudo add-apt-repository ppa:deadsnakes/ppa -y \
  && sudo apt update \
  && sudo apt install python3.8 python3.8-dev python3.8-distutils -y
# install pip for python3.8
RUN wget https://bootstrap.pypa.io/pip/3.8/get-pip.py -O get-pip.py \
  && python3.8 get-pip.py \
  && rm get-pip.py \
  && rm /usr/local/bin/pip3 \
  && ln -s /usr/local/bin/pip3.8 /usr/local/bin/pip3 \
  && python3.8 --version && pip3 --version

# install packages
RUN pip3 install --upgrade pip \
  && pip3 install --upgrade requests \
  && pip3 install --upgrade matplotlib \
  && pip3 install --upgrade numpy \
  && pip3 install --upgrade pandas \
  && pip3 install --upgrade openai \
  && pip3 install --upgrade networkx \
  && pip3 install --upgrade beautifulsoup4 \
  && pip3 install --upgrade watchdog \
  && pip3 install --upgrade idna \
  && pip3.6 install --upgrade watchdog \
  && pip3.6 install --upgrade beautifulsoup4 \
  && pip3.6 install --upgrade idna

# Install PEAR
RUN cd /tmp \
  && wget https://pear.php.net/go-pear.phar \
  && echo "" | php go-pear.phar \
  && rm go-pear.phar \
  && echo 'include_path = ".:/usr/share/php:/usr/share/pear:/usr/local/share/pear"' >> /usr/local/lib/php.ini \
  && pear channel-update pear.php.net || true
  
ENV PATH="/usr/local/php7.4/bin:${PATH}"
ENV PHP_INI_DIR="/usr/local/php7.4/etc"