BEGIN { a=0; }
(a==1) { a=0; print; }
/ALERT/ { a=1; }
