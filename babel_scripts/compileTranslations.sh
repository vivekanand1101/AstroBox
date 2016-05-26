# TO COMPILE TRANSLATIONS
# If we changed or added new translation strings to messages.po, then we need to run this.

echo "Compiling translations"
pybabel compile -d ../src/octoprint/translations --statistics
echo "========= COMPLETED ========="
echo "You'll be able to see the translation on the website!"
echo "============================="
