我的本意是开发一个加密脚本和解密脚本。
但因为加密交织的有些多，给自己绕蒙了，解密代码一堆bug
请不要将代码用于勒索病毒制作，仅供加密学习。
本人及其团队FteAPT不承担任何由不良操作引发的一系列法律问题。
#################
“加密初版”是第一代加密的雏形，它支持单文件加密。
使用方法
python 加密初版.py 需要加密的文件
回车会出现一个密码设定，输入你喜欢的密码，回车完成
################
“加密样版”是第二代加密的雏形，它支持了整个磁盘的加密，实现原文件和加密文件共存
使用方法
python 加密样版.py c:/
回车会出现一个密码设定，输入你喜欢的密码，回车完成
################
“加密风险版”是第二代加密的不建议版，它支持了整个磁盘的加密，删除原文件只保留加密文件（存在风险）
使用方法跟以上一样
python 加密风险版.py c:/
